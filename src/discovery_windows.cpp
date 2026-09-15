// Fabric Registry — Windows platform discovery adapter.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Discovery is not authority: this adapter reports what the local operating
// system can truthfully say about this host and never mutates the registry. It
// enumerates the adapter list with GetAdaptersAddresses, the permanent hardware
// address with GetIfEntry2, and Plug and Play network devices with SetupAPI.
//
// Every fact and every alias it produces is canonicalised by the core library
// before it reaches a caller. An input the library rejects is dropped and
// explained in the report diagnostics: a non-canonical fact never enters an
// observation, and a value is never silently truncated to fit a bound.
//
// This translation unit is compiled only on Windows. The portable entry points
// live in discovery_stub.cpp on every other platform, and
// DiscoveryReport::render() lives in discovery_common.cpp so that it is defined
// exactly once whichever adapter was compiled.

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <setupapi.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "fabric_registry/discovery.hpp"
#include "fabric_registry/entity.hpp"
#include "fabric_registry/identity.hpp"

namespace fabric_registry {
namespace {

// ---------------------------------------------------------------------------
// Constants and bounds
// ---------------------------------------------------------------------------

/// The exact flag set the adapter enumeration is required to use.
constexpr ULONG kAdapterFlags =
    static_cast<ULONG>(GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST);

/// First adapter-enumeration buffer. The documented two-call negotiation grows
/// it once; the ceiling keeps a pathological host from allocating without end.
constexpr ULONG kInitialAdapterBufferBytes = 15u * 1024u;
constexpr ULONG kMaximumAdapterBufferBytes = 1024u * 1024u;

constexpr unsigned long kIfTypeEthernetCsmacd = static_cast<unsigned long>(IF_TYPE_ETHERNET_CSMACD);
constexpr unsigned long kIfTypeIeee80211 = static_cast<unsigned long>(IF_TYPE_IEEE80211);
constexpr unsigned long kIfTypeSoftwareLoopback = static_cast<unsigned long>(IF_TYPE_SOFTWARE_LOOPBACK);
constexpr unsigned long kIfTypeTunnel = static_cast<unsigned long>(IF_TYPE_TUNNEL);

/// Upper bound on the characters of one Plug and Play device instance id.
constexpr std::size_t kDeviceInstanceIdChars = 512;

/// Largest physical address the interface manager reports (IF_MAX_PHYS_ADDRESS_LENGTH).
constexpr std::size_t kMaximumPhysicalAddressBytes = static_cast<std::size_t>(IF_MAX_PHYS_ADDRESS_LENGTH);

/// Mark used for "this adapter is not correlated with a Plug and Play device".
constexpr std::size_t kNoDevice = (std::numeric_limits<std::size_t>::max)();

/// Device class GUID of the Plug and Play network class
/// ({4d36e972-e325-11ce-bfc1-08002be10318}). Declared here instead of taking it
/// from devguid.h so the library never needs uuid.lib to link.
constexpr GUID kNetworkClassGuid = {0x4d36e972ul, 0xe325u, 0x11ceu,
                                    {0xbfu, 0xc1u, 0x08u, 0x00u, 0x2bu, 0xe1u, 0x03u, 0x18u}};

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

bool fits_limit(std::size_t max_string_bytes, std::string_view value) {
  return value.size() <= max_string_bytes;
}

/// Converts UTF-16 to UTF-8. An empty result means the operating system
/// refused the conversion or reported nothing; it is never treated as a name.
std::string utf8_from_wide(std::wstring_view text) {
  if (text.empty() || text.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
    return {};
  }
  const int length = static_cast<int>(text.size());
  const int required = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), length, nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return {};
  }
  std::string out(static_cast<std::size_t>(required), '\0');
  const int written = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), length, out.data(), required, nullptr, nullptr);
  if (written != required) {
    return {};
  }
  return out;
}

bool is_trimmed_wide(wchar_t value) {
  return value == L' ' || value == L'\t' || value == L'\r' || value == L'\n' || value == L'\v' || value == L'\f';
}

std::wstring_view trim_wide(std::wstring_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && is_trimmed_wide(text[begin])) {
    ++begin;
  }
  while (end > begin && is_trimmed_wide(text[end - 1])) {
    --end;
  }
  return text.substr(begin, end - begin);
}

char lowercase_ascii_char(char value) {
  if (value >= 'A' && value <= 'Z') {
    return static_cast<char>(value - 'A' + 'a');
  }
  return value;
}

std::string lowercase_ascii(std::string_view text) {
  std::string out(text);
  for (char& value : out) {
    value = lowercase_ascii_char(value);
  }
  return out;
}

bool is_ascii_hex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

template <class Integer>
std::string decimal_text(Integer value) {
  return std::to_string(static_cast<unsigned long long>(value));
}

/// Renders a physical address as lowercase hexadecimal without separators,
/// which is the canonical form the library expects for a MAC fact.
std::string mac_text(const unsigned char* address, std::size_t length) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(length * 2);
  for (std::size_t index = 0; index < length; ++index) {
    const unsigned char byte = address[index];
    out.push_back(kDigits[(byte >> 4) & 0x0Fu]);
    out.push_back(kDigits[byte & 0x0Fu]);
  }
  return out;
}

/// True when bit 0x02 of the first octet is clear. The canonicaliser rejects a
/// locally administered address as PermanentMac, so it is checked here first.
bool is_universally_administered(const unsigned char* address, std::size_t length) {
  return length != 0 && (address[0] & 0x02u) == 0u;
}

/// An all-zero address is what the interface manager reports when it has no
/// permanent address at all. It is the absence of an address, not an address.
bool is_zero_address(const unsigned char* address, std::size_t length) {
  for (std::size_t index = 0; index < length; ++index) {
    if (address[index] != 0u) {
      return false;
    }
  }
  return true;
}

/// Renders a PCI address in the canonical "0000:3b:00.0" form.
std::string format_pci_address(unsigned domain, unsigned bus, unsigned device, unsigned function) {
  static constexpr char kDigits[] = "0123456789abcdef";
  const auto append_hex = [](std::string& out, unsigned value, unsigned width) {
    for (unsigned shift = width; shift > 0; --shift) {
      out.push_back(kDigits[(value >> ((shift - 1u) * 4u)) & 0x0Fu]);
    }
  };
  std::string out;
  out.reserve(12);
  append_hex(out, domain, 4);
  out.push_back(':');
  append_hex(out, bus, 2);
  out.push_back(':');
  append_hex(out, device, 2);
  out.push_back('.');
  append_hex(out, function, 1);
  return out;
}

bool find_wide_keyword(std::wstring_view text, std::size_t from, std::wstring_view keyword, std::size_t& at) {
  if (keyword.empty() || text.size() < keyword.size()) {
    return false;
  }
  for (std::size_t index = from; index + keyword.size() <= text.size(); ++index) {
    bool matched = true;
    for (std::size_t offset = 0; offset < keyword.size(); ++offset) {
      wchar_t value = text[index + offset];
      if (value >= L'A' && value <= L'Z') {
        value = static_cast<wchar_t>(value - L'A' + L'a');
      }
      if (value != keyword[offset]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      at = index;
      return true;
    }
  }
  return false;
}

/// Reads "<keyword> <decimal>" starting at or after \`cursor\`.
bool read_wide_keyword_number(std::wstring_view text, std::size_t& cursor, std::wstring_view keyword, unsigned& value) {
  std::size_t at = 0;
  if (!find_wide_keyword(text, cursor, keyword, at)) {
    return false;
  }
  std::size_t index = at + keyword.size();
  while (index < text.size() && !(text[index] >= L'0' && text[index] <= L'9')) {
    if (text[index] != L' ' && text[index] != L'\t') {
      return false;
    }
    ++index;
  }
  if (index >= text.size()) {
    return false;
  }
  unsigned parsed = 0;
  while (index < text.size() && text[index] >= L'0' && text[index] <= L'9') {
    parsed = parsed * 10u + static_cast<unsigned>(text[index] - L'0');
    if (parsed > 0xFFFFu) {
      return false;
    }
    ++index;
  }
  cursor = index;
  value = parsed;
  return true;
}

/// Parses the Plug and Play location information of a PCI device, which Windows
/// reports as "PCI bus 3, device 0, function 0". Returns an empty string when
/// the text is not a PCI location.
std::string parse_pci_location(std::wstring_view location) {
  std::size_t cursor = 0;
  unsigned bus = 0;
  unsigned device = 0;
  unsigned function = 0;
  if (!read_wide_keyword_number(location, cursor, L"bus", bus)) {
    return {};
  }
  if (!read_wide_keyword_number(location, cursor, L"device", device)) {
    return {};
  }
  if (!read_wide_keyword_number(location, cursor, L"function", function)) {
    return {};
  }
  if (bus > 0xFFu || device > 0xFFu || function > 0x0Fu) {
    return {};
  }
  // Windows reports no PCI segment here, so the domain is the default segment.
  return format_pci_address(0u, bus, device, function);
}

/// Copies an exactly \`digits\` wide hexadecimal field that follows \`marker\`.
bool extract_hex_field(std::string_view lowered, std::string_view marker, std::size_t digits, std::string& out) {
  const std::size_t position = lowered.find(marker);
  if (position == std::string_view::npos) {
    return false;
  }
  const std::size_t begin = position + marker.size();
  if (begin + digits > lowered.size()) {
    return false;
  }
  for (std::size_t index = 0; index < digits; ++index) {
    if (!is_ascii_hex(lowered[begin + index])) {
      return false;
    }
  }
  out = lowercase_ascii(lowered.substr(begin, digits));
  return true;
}

/// Collects every maximal hexadecimal run of exactly twelve characters. Network
/// drivers publish such a run in a NETCARD-style hardware id, which is how a
/// driver stack ties a Plug and Play device to an operating system adapter.
void collect_mac_tokens(std::string_view text, std::vector<std::string>& out) {
  std::size_t index = 0;
  while (index < text.size()) {
    if (!is_ascii_hex(text[index])) {
      ++index;
      continue;
    }
    const std::size_t start = index;
    while (index < text.size() && is_ascii_hex(text[index])) {
      ++index;
    }
    if (index - start == 12) {
      out.push_back(lowercase_ascii(text.substr(start, 12)));
    }
  }
}

// ---------------------------------------------------------------------------
// Enumeration records
// ---------------------------------------------------------------------------

/// One adapter as the operating system reports it, already converted to UTF-8.
struct HostAdapter {
  std::string adapter_name;
  std::string friendly_name;
  std::string description;
  unsigned long if_type{0};
  unsigned long if_index{0};
  std::size_t address_length{0};
  std::vector<unsigned char> current_address;
  std::vector<unsigned char> permanent_address;
};

/// One Plug and Play network device as SetupAPI reports it.
struct PnpNetworkDevice {
  std::string instance_id;
  std::string description;
  std::string friendly_name;
  std::string location;
  std::string pci_address;
  std::string vendor_id;
  std::string product_id;
  std::string subsystem_id;
  std::string subsystem_text;
  std::vector<std::string> hardware_ids;
  std::vector<std::string> mac_tokens;
  bool claimed{false};
};

/// Identity of the enumerating host, and the scope a device instance id is only
/// meaningful inside.
struct HostContext {
  std::string host_name;
  std::string device_scope;
};

// ---------------------------------------------------------------------------
// Fact, alias and metadata emission
// ---------------------------------------------------------------------------

/// Writes canonical identity into one observation and explains every value the
/// library rejects. It is the only path by which identity enters an
/// observation, so a non-canonical fact cannot be produced by construction.
class FactWriter {
public:
  FactWriter(DiscoveryObservation& observation,
             const DiscoveryOptions& options,
             std::string subject,
             std::vector<std::string>& diagnostics)
      : observation_(observation), options_(options), subject_(std::move(subject)), diagnostics_(diagnostics) {}

  void fact(IdentityFactKind kind, std::string_view scope, std::string_view value) {
    if (observation_.facts.size() >= options_.max_facts) {
      diagnostics_.push_back(subject_ + ": " + std::string(to_string(kind)) +
                             " dropped: the per-observation fact bound was reached");
      return;
    }
    const FactResult result = canonicalize_fact(kind, scope, value, options_.max_string_bytes);
    if (!result) {
      diagnostics_.push_back(subject_ + ": " + std::string(to_string(kind)) + " rejected: " +
                             std::string(to_string(result.issue)));
      return;
    }
    observation_.facts.push_back(*result.fact);
  }

  void alias(AliasNamespace alias_namespace, std::string_view value) {
    const AliasNameResult result = canonicalize_alias(alias_namespace, value, options_.max_string_bytes);
    if (!result) {
      diagnostics_.push_back(subject_ + ": alias " + std::string(to_string(alias_namespace)) + " rejected: " +
                             std::string(to_string(result.issue)));
      return;
    }
    observation_.aliases.push_back(AliasInput{alias_namespace, result.name->value});
  }

  void metadata(std::string_view key, std::string_view value) {
    if (!fits_limit(options_.max_string_bytes, key) || !fits_limit(options_.max_string_bytes, value)) {
      diagnostics_.push_back(subject_ + ": metadata " + std::string(key) +
                             " dropped: the entry exceeds the configured string limit");
      return;
    }
    observation_.metadata.push_back(MetadataEntry{std::string(key), std::string(value)});
  }

private:
  DiscoveryObservation& observation_;
  const DiscoveryOptions& options_;
  std::string subject_;
  std::vector<std::string>& diagnostics_;
};

/// Adds one observation unless the observation bound is already reached. The
/// report is marked truncated only when something was actually dropped.
void add_observation(DiscoveryReport& report, const DiscoveryOptions& options, DiscoveryObservation observation) {
  if (report.observations.size() >= options.max_observations) {
    report.truncated = true;
    return;
  }
  report.observations.push_back(std::move(observation));
}

/// Builds the diagnostic subject of an adapter. The publisher name is included
/// only when it is bounded, so a diagnostic never carries an unbounded string.
std::string adapter_subject(const HostAdapter& adapter, std::size_t max_string_bytes) {
  if (adapter.friendly_name.empty() || !fits_limit(max_string_bytes, adapter.friendly_name)) {
    return adapter.adapter_name;
  }
  return adapter.adapter_name + " (" + adapter.friendly_name + ")";
}

// ---------------------------------------------------------------------------
// Adapter enumeration
// ---------------------------------------------------------------------------

/// Fills in the permanent physical address of one adapter. MIB_IF_ROW2 is the
/// only Windows structure that carries it; when the query fails the current
/// address from GetAdaptersAddresses remains the reported one.
void read_interface_addresses(HostAdapter& adapter, const IP_ADAPTER_ADDRESSES& entry, std::size_t current_length) {
  adapter.address_length = current_length;
  MIB_IF_ROW2 row{};
  row.InterfaceLuid = entry.Luid;
  row.InterfaceIndex = entry.IfIndex;
  if (::GetIfEntry2(&row) != NO_ERROR) {
    return;
  }
  const std::size_t permanent_length = (std::min)(static_cast<std::size_t>(row.PhysicalAddressLength),
                                                 kMaximumPhysicalAddressBytes);
  adapter.permanent_address.assign(row.PermanentPhysicalAddress, row.PermanentPhysicalAddress + permanent_length);
  adapter.address_length = (std::max)(current_length, permanent_length);
}

void enumerate_host_adapters(std::vector<HostAdapter>& adapters, std::vector<std::string>& diagnostics) {
  ULONG size = kInitialAdapterBufferBytes;
  std::vector<unsigned char> buffer(static_cast<std::size_t>(size), 0);
  ULONG status = ::GetAdaptersAddresses(static_cast<ULONG>(AF_UNSPEC), kAdapterFlags, nullptr,
                                        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &size);
  if (status == ERROR_BUFFER_OVERFLOW) {
    if (size == 0 || size > kMaximumAdapterBufferBytes) {
      diagnostics.push_back("GetAdaptersAddresses: the adapter list requires " + decimal_text(size) +
                            " bytes, which exceeds the 1 MiB bound; no adapter was enumerated");
      return;
    }
    buffer.assign(static_cast<std::size_t>(size), 0);
    status = ::GetAdaptersAddresses(static_cast<ULONG>(AF_UNSPEC), kAdapterFlags, nullptr,
                                    reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &size);
    if (status == ERROR_BUFFER_OVERFLOW) {
      diagnostics.push_back("GetAdaptersAddresses: the adapter list grew between the size negotiation and the "
                            "enumeration; no adapter was enumerated");
      return;
    }
  }
  if (status != NO_ERROR) {
    diagnostics.push_back("GetAdaptersAddresses failed with status " + decimal_text(status) +
                          "; no adapter was enumerated");
    return;
  }

  for (PIP_ADAPTER_ADDRESSES entry = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()); entry != nullptr;
       entry = entry->Next) {
    const std::size_t current_length =
        (std::min)(static_cast<std::size_t>(entry->PhysicalAddressLength),
                   static_cast<std::size_t>(MAX_ADAPTER_ADDRESS_LENGTH));
    HostAdapter adapter;
    adapter.if_type = static_cast<unsigned long>(entry->IfType);
    adapter.if_index = static_cast<unsigned long>(entry->IfIndex);
    adapter.current_address.assign(entry->PhysicalAddress, entry->PhysicalAddress + current_length);
    if (entry->AdapterName != nullptr) {
      adapter.adapter_name.assign(entry->AdapterName);
    }
    if (entry->FriendlyName != nullptr) {
      adapter.friendly_name = utf8_from_wide(trim_wide(std::wstring_view(entry->FriendlyName)));
    }
    if (entry->Description != nullptr) {
      adapter.description = utf8_from_wide(trim_wide(std::wstring_view(entry->Description)));
    }
    read_interface_addresses(adapter, *entry, current_length);

    const bool ethernet_class =
        adapter.if_type == kIfTypeEthernetCsmacd || adapter.if_type == kIfTypeIeee80211;
    const bool excluded = adapter.if_type == kIfTypeSoftwareLoopback || adapter.if_type == kIfTypeTunnel;
    const bool address_bearing = adapter.address_length == 6 || adapter.address_length == 8 ||
                                 adapter.address_length == 20;
    if (excluded || (!ethernet_class && !address_bearing)) {
      continue;
    }
    if (adapter.adapter_name.empty()) {
      diagnostics.push_back("adapter: skipped: GetAdaptersAddresses reported no interface GUID");
      continue;
    }
    adapters.push_back(std::move(adapter));
  }
}

// ---------------------------------------------------------------------------
// Plug and Play enumeration
// ---------------------------------------------------------------------------

/// Reads one textual device registry property. Missing properties are normal
/// (not every device publishes a friendly name) and are not diagnosed.
bool read_device_property(HDEVINFO set, SP_DEVINFO_DATA& info, DWORD property, std::vector<std::wstring>& out) {
  out.clear();
  DWORD type = 0;
  DWORD required = 0;
  ::SetLastError(ERROR_SUCCESS);
  if (::SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type, nullptr, 0, &required)) {
    return false;
  }
  if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0) {
    return false;
  }
  std::vector<wchar_t> buffer(static_cast<std::size_t>(required) / sizeof(wchar_t) + 2, L'\0');
  DWORD written = 0;
  if (!::SetupDiGetDeviceRegistryPropertyW(set, &info, property, &type, reinterpret_cast<PBYTE>(buffer.data()),
                                           static_cast<DWORD>(buffer.size() * sizeof(wchar_t)), &written)) {
    return false;
  }
  const std::size_t limit = (std::min)(static_cast<std::size_t>(written) / sizeof(wchar_t), buffer.size());
  if (type == REG_MULTI_SZ) {
    std::size_t start = 0;
    while (start < limit) {
      std::size_t end = start;
      while (end < limit && buffer[end] != L'\0') {
        ++end;
      }
      if (end == start) {
        break;
      }
      out.emplace_back(buffer.data() + start, end - start);
      start = end + 1;
    }
  } else {
    std::size_t length = 0;
    while (length < limit && buffer[length] != L'\0') {
      ++length;
    }
    if (length != 0) {
      out.emplace_back(buffer.data(), length);
    }
  }
  return !out.empty();
}

std::string read_device_instance_id(HDEVINFO set, SP_DEVINFO_DATA& info) {
  std::vector<wchar_t> buffer(kDeviceInstanceIdChars, L'\0');
  if (!::SetupDiGetDeviceInstanceIdW(set, &info, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr)) {
    return {};
  }
  return utf8_from_wide(trim_wide(std::wstring_view(buffer.data())));
}

/// Interprets the hardware ids of one device: the PCI identity of the bus
/// enumerator and every MAC-like token a driver published.
void read_hardware_ids(const std::vector<std::wstring>& values, PnpNetworkDevice& device) {
  for (const std::wstring& value : values) {
    std::string identifier = utf8_from_wide(trim_wide(value));
    if (identifier.empty()) {
      continue;
    }
    collect_mac_tokens(identifier, device.mac_tokens);
    device.hardware_ids.push_back(std::move(identifier));
  }
  for (const std::string& identifier : device.hardware_ids) {
    const std::string lowered = lowercase_ascii(identifier);
    if (lowered.compare(0, 4, "pci\\") != 0) {
      continue;
    }
    extract_hex_field(lowered, "ven_", 4, device.vendor_id);
    extract_hex_field(lowered, "dev_", 4, device.product_id);
    if (extract_hex_field(lowered, "subsys_", 8, device.subsystem_text)) {
      // The library models a 16-bit PCI subsystem identifier, so the fact takes
      // the subsystem device identifier and the full field is kept as metadata.
      device.subsystem_id = device.subsystem_text.substr(0, 4);
    }
    break;
  }
}

void enumerate_pnp_network_devices(std::vector<PnpNetworkDevice>& devices, std::vector<std::string>& diagnostics) {
  HDEVINFO set = ::SetupDiGetClassDevsW(&kNetworkClassGuid, nullptr, nullptr, DIGCF_PRESENT);
  if (set == INVALID_HANDLE_VALUE) {
    diagnostics.push_back("SetupDiGetClassDevsW(net class) failed with error " + decimal_text(::GetLastError()) +
                          "; no Plug and Play network device was enumerated");
    return;
  }
  SP_DEVINFO_DATA info{};
  for (DWORD index = 0;; ++index) {
    info.cbSize = sizeof(info);
    if (!::SetupDiEnumDeviceInfo(set, index, &info)) {
      const DWORD error = ::GetLastError();
      if (error != ERROR_NO_MORE_ITEMS) {
        diagnostics.push_back("SetupDiEnumDeviceInfo stopped with error " + decimal_text(error) +
                              "; the Plug and Play device list is incomplete");
      }
      break;
    }
    PnpNetworkDevice device;
    device.instance_id = read_device_instance_id(set, info);
    if (device.instance_id.empty()) {
      diagnostics.push_back("Plug and Play network device: skipped: SetupDiGetDeviceInstanceIdW failed with error " +
                            decimal_text(::GetLastError()));
      continue;
    }
    std::vector<std::wstring> values;
    if (read_device_property(set, info, SPDRP_DEVICEDESC, values)) {
      device.description = utf8_from_wide(trim_wide(values.front()));
    }
    if (read_device_property(set, info, SPDRP_FRIENDLYNAME, values)) {
      device.friendly_name = utf8_from_wide(trim_wide(values.front()));
    }
    if (read_device_property(set, info, SPDRP_LOCATION_INFORMATION, values)) {
      const std::wstring_view location = trim_wide(values.front());
      device.location = utf8_from_wide(location);
      device.pci_address = parse_pci_location(location);
    }
    if (read_device_property(set, info, SPDRP_HARDWAREID, values)) {
      read_hardware_ids(values, device);
    }
    devices.push_back(std::move(device));
  }
  ::SetupDiDestroyDeviceInfoList(set);
}

// ---------------------------------------------------------------------------
// Correlating an adapter with its Plug and Play device
// ---------------------------------------------------------------------------

/// Windows appends " #<n>" to the description of the second and later devices
/// that share one driver description. The suffix disambiguates two instances of
/// the same device and is not part of what is matched.
std::string strip_duplicate_suffix(std::string lowered) {
  std::size_t position = lowered.size();
  while (position > 0 && lowered[position - 1] >= '0' && lowered[position - 1] <= '9') {
    --position;
  }
  if (position == lowered.size() || position < 2) {
    return lowered;
  }
  if (lowered[position - 1] == '#' && lowered[position - 2] == ' ') {
    lowered.resize(position - 2);
  }
  return lowered;
}

std::string adapter_match_key(const HostAdapter& adapter, bool normalize_suffix) {
  const std::string lowered = lowercase_ascii(adapter.description.empty() ? adapter.friendly_name
                                                                         : adapter.description);
  return normalize_suffix ? strip_duplicate_suffix(lowered) : lowered;
}

std::string device_match_key(const PnpNetworkDevice& device, bool normalize_suffix) {
  const std::string lowered = lowercase_ascii(device.description.empty() ? device.friendly_name
                                                                        : device.description);
  return normalize_suffix ? strip_duplicate_suffix(lowered) : lowered;
}

/// Pairs the adapters that are still unpaired with the devices that are still
/// unclaimed and carry the same description, but only when that description
/// names exactly one adapter and exactly one device. Ambiguity is never
/// resolved by guesswork.
void match_unique_descriptions(const std::vector<HostAdapter>& adapters,
                               std::vector<PnpNetworkDevice>& devices,
                               std::vector<std::size_t>& pairing,
                               bool normalize_suffix) {
  std::unordered_map<std::string, std::size_t> adapter_keys;
  for (std::size_t adapter_index = 0; adapter_index < adapters.size(); ++adapter_index) {
    if (pairing[adapter_index] != kNoDevice) {
      continue;
    }
    const std::string key = adapter_match_key(adapters[adapter_index], normalize_suffix);
    if (!key.empty()) {
      ++adapter_keys[key];
    }
  }
  std::unordered_map<std::string, std::size_t> device_keys;
  for (const PnpNetworkDevice& device : devices) {
    if (device.claimed) {
      continue;
    }
    const std::string key = device_match_key(device, normalize_suffix);
    if (!key.empty()) {
      ++device_keys[key];
    }
  }
  for (std::size_t adapter_index = 0; adapter_index < adapters.size(); ++adapter_index) {
    if (pairing[adapter_index] != kNoDevice) {
      continue;
    }
    const std::string key = adapter_match_key(adapters[adapter_index], normalize_suffix);
    if (key.empty() || adapter_keys[key] != 1 || device_keys[key] != 1) {
      continue;
    }
    for (std::size_t device_index = 0; device_index < devices.size(); ++device_index) {
      if (devices[device_index].claimed ||
          device_match_key(devices[device_index], normalize_suffix) != key) {
        continue;
      }
      pairing[adapter_index] = device_index;
      devices[device_index].claimed = true;
      break;
    }
  }
}

/// Pairs every adapter with the Plug and Play device that owns it. A MAC token
/// published in a hardware id is authoritative; a description is used only when
/// it is unique on both sides, so two identical devices are never paired by
/// guesswork.
void correlate_devices(const std::vector<HostAdapter>& adapters,
                       std::vector<PnpNetworkDevice>& devices,
                       std::vector<std::size_t>& pairing) {
  pairing.assign(adapters.size(), kNoDevice);
  for (std::size_t adapter_index = 0; adapter_index < adapters.size(); ++adapter_index) {
    const HostAdapter& adapter = adapters[adapter_index];
    std::vector<std::string> keys;
    if (adapter.current_address.size() == 6) {
      keys.push_back(mac_text(adapter.current_address.data(), adapter.current_address.size()));
    }
    if (adapter.permanent_address.size() == 6) {
      keys.push_back(mac_text(adapter.permanent_address.data(), adapter.permanent_address.size()));
    }
    for (const std::string& key : keys) {
      bool matched = false;
      for (std::size_t device_index = 0; device_index < devices.size(); ++device_index) {
        if (devices[device_index].claimed) {
          continue;
        }
        const std::vector<std::string>& tokens = devices[device_index].mac_tokens;
        if (std::find(tokens.begin(), tokens.end(), key) != tokens.end()) {
          pairing[adapter_index] = device_index;
          devices[device_index].claimed = true;
          matched = true;
          break;
        }
      }
      if (matched) {
        break;
      }
    }
  }

  match_unique_descriptions(adapters, devices, pairing, false);
  match_unique_descriptions(adapters, devices, pairing, true);
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

void emit_adapter_observation(const HostAdapter& adapter,
                              const PnpNetworkDevice* device,
                              const HostContext& host,
                              const DiscoveryOptions& options,
                              DiscoveryReport& report) {
  const std::string display_name =
      adapter.friendly_name.empty() ? adapter.description : adapter.friendly_name;
  if (!fits_limit(options.max_string_bytes, display_name) ||
      !fits_limit(options.max_string_bytes, adapter.adapter_name)) {
    report.diagnostics.push_back("adapter " + adapter.adapter_name +
                                 ": observation skipped: a produced string exceeds the configured limit of " +
                                 decimal_text(options.max_string_bytes) + " bytes");
    return;
  }

  DiscoveryObservation observation;
  observation.entity_class = EntityClass::Nic;
  observation.friendly_name = display_name;
  observation.platform_detail = adapter.adapter_name;
  observation.scope = options.scope;
  observation.provenance.source = ObservationSource::LocalHostEnumeration;
  observation.provenance.validity_class = ProvenanceClass::Real;
  observation.provenance.mechanism = "GetAdaptersAddresses";
  observation.provenance.source_identity = host.host_name;

  FactWriter writer(observation, options, adapter_subject(adapter, options.max_string_bytes), report.diagnostics);

  if (adapter.permanent_address.size() == 6 && is_universally_administered(adapter.permanent_address.data(), 6) &&
      !is_zero_address(adapter.permanent_address.data(), 6)) {
    writer.fact(IdentityFactKind::PermanentMac, std::string_view(),
                mac_text(adapter.permanent_address.data(), 6));
  }
  if (adapter.current_address.size() == 6) {
    writer.fact(IdentityFactKind::MacAddress, std::string_view(), mac_text(adapter.current_address.data(), 6));
  }
  if (!adapter.friendly_name.empty()) {
    writer.fact(IdentityFactKind::FriendlyName, std::string_view(), adapter.friendly_name);
  }
  if (!adapter.description.empty()) {
    writer.fact(IdentityFactKind::DeviceModel, std::string_view(), adapter.description);
  }
  if (device != nullptr) {
    writer.fact(IdentityFactKind::DeviceInstanceId, host.device_scope, device->instance_id);
    if (!device->pci_address.empty()) {
      writer.fact(IdentityFactKind::PciAddress, std::string_view(), device->pci_address);
    }
  }
  writer.alias(AliasNamespace::VendorGuid, adapter.adapter_name);
  if (!host.host_name.empty()) {
    writer.alias(AliasNamespace::HostName, host.host_name);
  }
  // "oper-status" is live state, not identity, and must never enter the
  // registry, so it is deliberately absent from this metadata.
  writer.metadata("if-type", decimal_text(adapter.if_type));
  writer.metadata("if-index", decimal_text(adapter.if_index));
  writer.metadata("adapter-name", adapter.adapter_name);

  add_observation(report, options, std::move(observation));
}

void emit_device_observation(const PnpNetworkDevice& device,
                             const HostContext& host,
                             const DiscoveryOptions& options,
                             DiscoveryReport& report) {
  std::string display_name = device.friendly_name.empty() ? device.description : device.friendly_name;
  if (display_name.empty()) {
    display_name = device.instance_id;
  }
  if (!fits_limit(options.max_string_bytes, display_name)) {
    report.diagnostics.push_back(device.instance_id +
                                 ": observation skipped: a produced string exceeds the configured limit of " +
                                 decimal_text(options.max_string_bytes) + " bytes");
    return;
  }

  DiscoveryObservation observation;
  observation.entity_class = EntityClass::Nic;
  observation.friendly_name = display_name;
  observation.platform_detail = device.instance_id;
  observation.scope = options.scope;
  observation.provenance.source = ObservationSource::LocalHostEnumeration;
  observation.provenance.validity_class = ProvenanceClass::Real;
  observation.provenance.mechanism = "SetupDiGetClassDevsW";
  observation.provenance.source_identity = host.host_name;

  FactWriter writer(observation, options, device.instance_id, report.diagnostics);
  writer.fact(IdentityFactKind::DeviceInstanceId, host.device_scope, device.instance_id);
  if (!device.pci_address.empty()) {
    writer.fact(IdentityFactKind::PciAddress, std::string_view(), device.pci_address);
  }
  if (!device.vendor_id.empty()) {
    writer.fact(IdentityFactKind::VendorId, std::string_view(), device.vendor_id);
  }
  if (!device.product_id.empty()) {
    writer.fact(IdentityFactKind::ProductId, std::string_view(), device.product_id);
  }
  if (!device.subsystem_id.empty()) {
    writer.fact(IdentityFactKind::SubsystemId, std::string_view(), device.subsystem_id);
  }
  if (!device.description.empty()) {
    writer.fact(IdentityFactKind::DeviceModel, std::string_view(), device.description);
  }
  if (!device.location.empty()) {
    writer.metadata("location-information", device.location);
  }
  if (!device.subsystem_text.empty()) {
    writer.metadata("subsystem-id", device.subsystem_text);
  }
  if (!device.hardware_ids.empty()) {
    writer.metadata("hardware-id", device.hardware_ids.front());
  }

  add_observation(report, options, std::move(observation));
}

void emit_host_observation(const HostContext& host, const DiscoveryOptions& options, DiscoveryReport& report) {
  if (host.host_name.empty()) {
    report.diagnostics.push_back("host identity: skipped: GetComputerNameExW reported no computer name");
    return;
  }
  DiscoveryObservation observation;
  observation.entity_class = EntityClass::Host;
  observation.friendly_name = host.host_name;
  observation.platform_detail = "GetComputerNameExW(ComputerNamePhysicalDnsHostname)";
  observation.scope = options.scope;
  observation.provenance.source = ObservationSource::LocalHostEnumeration;
  observation.provenance.validity_class = ProvenanceClass::Real;
  observation.provenance.mechanism = "GetComputerNameExW";
  observation.provenance.source_identity = host.host_name;

  FactWriter writer(observation, options, "host " + host.host_name, report.diagnostics);
  writer.fact(IdentityFactKind::HostName, std::string_view(), host.host_name);
  // The local system has no Plug and Play instance id of its own, so the host
  // is identified by its name inside the scope the name was issued in. This is
  // the strong fact that lets a host record derive a canonical identity.
  writer.fact(IdentityFactKind::DeviceInstanceId, host.device_scope, host.host_name);
  writer.alias(AliasNamespace::HostName, host.host_name);

  add_observation(report, options, std::move(observation));
}

} // namespace

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

std::string_view to_string(DiscoveryCapability value) noexcept {
  switch (value) {
    case DiscoveryCapability::HostNetworkAdapters:
      return "host-network-adapters";
    case DiscoveryCapability::PciNetworkDevices:
      return "pci-network-devices";
    case DiscoveryCapability::HostIdentity:
      return "host-identity";
    case DiscoveryCapability::AcceleratorDevices:
      return "accelerator-devices";
    case DiscoveryCapability::RdmaDevices:
      return "rdma-devices";
    case DiscoveryCapability::PhysicalSwitches:
      return "physical-switches";
    case DiscoveryCapability::OpticalLinks:
      return "optical-links";
    case DiscoveryCapability::SmartNicDpu:
      return "smart-nic-dpu";
  }
  return "unknown";
}

std::string_view to_string(CapabilityStatus value) noexcept {
  switch (value) {
    case CapabilityStatus::Available:
      return "available";
    case CapabilityStatus::Empty:
      return "empty";
    case CapabilityStatus::Unsupported:
      return "unsupported";
  }
  return "unknown";
}

std::vector<CapabilityReport> discovery_capabilities() {
  std::vector<CapabilityReport> reports;
  reports.reserve(kDiscoveryCapabilityCount);
  reports.push_back({DiscoveryCapability::HostNetworkAdapters, CapabilityStatus::Available,
                     "GetAdaptersAddresses enumerates the host network adapter list on Windows"});
  reports.push_back({DiscoveryCapability::PciNetworkDevices, CapabilityStatus::Available,
                     "SetupAPI enumerates present Plug and Play network devices on Windows"});
  reports.push_back({DiscoveryCapability::HostIdentity, CapabilityStatus::Available,
                     "GetComputerNameExW(ComputerNamePhysicalDnsHostname) reports the local computer name"});
  reports.push_back({DiscoveryCapability::AcceleratorDevices, CapabilityStatus::Unsupported,
                     "GPU, FPGA and inference accelerator enumeration is outside Fabric Registry's systems "
                     "boundary; no accelerator library is part of this build"});
  reports.push_back({DiscoveryCapability::RdmaDevices, CapabilityStatus::Unsupported,
                     "RDMA host channel adapter enumeration requires a vendor or network-direct provider library "
                     "that this build does not have"});
  reports.push_back({DiscoveryCapability::PhysicalSwitches, CapabilityStatus::Unsupported,
                     "physical switch discovery requires a fabric controller or device agent and is outside the "
                     "boundary of a local host adapter"});
  reports.push_back({DiscoveryCapability::OpticalLinks, CapabilityStatus::Unsupported,
                     "optical link and transceiver state belongs to Link State Fabric; no optical module library "
                     "is part of this build"});
  reports.push_back({DiscoveryCapability::SmartNicDpu, CapabilityStatus::Unsupported,
                     "SmartNIC and DPU enumeration requires vendor management hardware and library support that "
                     "this build does not have"});
  return reports;
}

std::string local_host_identity() {
  DWORD size = 0;
  ::GetComputerNameExW(ComputerNamePhysicalDnsHostname, nullptr, &size);
  if (size == 0) {
    return {};
  }
  std::wstring buffer(static_cast<std::size_t>(size), L'\0');
  if (!::GetComputerNameExW(ComputerNamePhysicalDnsHostname, buffer.data(), &size)) {
    return {};
  }
  buffer.resize(static_cast<std::size_t>(size));
  return utf8_from_wide(buffer);
}

DiscoveryReport discover_local_host(const DiscoveryOptions& options) {
  DiscoveryReport report;
  report.platform = "windows";
  report.source = ObservationSource::LocalHostEnumeration;
  report.validity_class = ProvenanceClass::Real;
  report.capabilities = discovery_capabilities();

  try {
    HostContext host;
    const std::string host_name = local_host_identity();
    if (!host_name.empty() && fits_limit(options.max_string_bytes, host_name)) {
      host.host_name = host_name;
      host.device_scope = "host:" + host_name;
    } else if (!host_name.empty()) {
      report.diagnostics.push_back("host name: omitted: it exceeds the configured limit of " +
                                   decimal_text(options.max_string_bytes) +
                                   " bytes, so host-scoped facts and aliases are not produced");
    }

    std::vector<HostAdapter> adapters;
    enumerate_host_adapters(adapters, report.diagnostics);

    // The Plug and Play list is always read: it is what gives an adapter its
    // device instance id and PCI address. options.include_pci_devices controls
    // whether devices without an adapter observation are reported as well.
    std::vector<PnpNetworkDevice> devices;
    enumerate_pnp_network_devices(devices, report.diagnostics);

    std::vector<std::size_t> pairing;
    correlate_devices(adapters, devices, pairing);

    std::unordered_set<std::string> emitted_devices;
    for (std::size_t index = 0; index < adapters.size() && !report.truncated; ++index) {
      const PnpNetworkDevice* device = nullptr;
      if (pairing[index] != kNoDevice) {
        device = &devices[pairing[index]];
        emitted_devices.insert(lowercase_ascii(device->instance_id));
      }
      emit_adapter_observation(adapters[index], device, host, options, report);
    }

    if (options.include_pci_devices) {
      for (const PnpNetworkDevice& device : devices) {
        if (report.truncated) {
          break;
        }
        if (device.claimed || emitted_devices.count(lowercase_ascii(device.instance_id)) != 0) {
          continue;
        }
        emitted_devices.insert(lowercase_ascii(device.instance_id));
        emit_device_observation(device, host, options, report);
      }
    }

    if (options.include_host_identity && !report.truncated) {
      emit_host_observation(host, options, report);
    }
  } catch (...) {
    // The enumeration genuinely ran; only the report is incomplete.
    report.diagnostics.push_back("discovery: an unexpected error interrupted the enumeration; the report is "
                                 "incomplete but the observations it carries are real");
  }
  return report;
}

} // namespace fabric_registry

#endif // defined(_WIN32)
