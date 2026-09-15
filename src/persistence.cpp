// Fabric Registry — versioned, integrity-checked durable state.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/persistence.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <system_error>

#include "fabric_registry/codec.hpp"
#include "fabric_registry/digest.hpp"
#include "fabric_registry/record_codec.hpp"
#include "fabric_registry/version.hpp"
#include "registry_internal.hpp"

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fabric_registry {
namespace persistence {

namespace {

/// Upper bound applied to a state file before it is read into memory. A file
/// larger than this is refused without allocating anything for it.
constexpr std::uint64_t kMaxStateFileBytes = 1ull << 32;

constexpr std::uint32_t kReservedHeaderWord = 0;

void append_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int shift = 0; shift < 64; shift += 8) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

std::uint64_t read_le64(const std::uint8_t* data) noexcept {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8u * static_cast<unsigned>(i));
  }
  return value;
}

std::uint32_t read_le32(const std::uint8_t* data) noexcept {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data[i]) << (8u * static_cast<unsigned>(i));
  }
  return value;
}

/// Header + integrity check only. Used to validate what actually reached the
/// disk without paying for a full semantic decode.
Outcome verify_image(std::span<const std::uint8_t> image) {
  if (image.size() < kHeaderBytes + kIntegrityBytes) {
    return Outcome(OutcomeCode::PersistenceFailure, "the written state file is shorter than its fixed header");
  }
  if (std::memcmp(image.data(), kMagic, sizeof(kMagic)) != 0) {
    return Outcome(OutcomeCode::IntegrityFailure, "the written state file does not carry the expected magic");
  }
  const std::uint64_t declared = read_le64(image.data() + 16);
  if (declared != image.size() - kHeaderBytes - kIntegrityBytes) {
    return Outcome(OutcomeCode::IntegrityFailure,
                   "the written state file declares a payload length that does not match its size");
  }
  const std::span<const std::uint8_t> payload = image.subspan(kHeaderBytes, static_cast<std::size_t>(declared));
  const DigestBytes digest = Sha256::hash(payload.data(), payload.size());
  if (std::memcmp(digest.data(), image.data() + kHeaderBytes + declared, 8) != 0) {
    return Outcome(OutcomeCode::IntegrityFailure, "the written state file failed its integrity digest");
  }
  return Outcome(OutcomeCode::Committed, "state image verified");
}

std::vector<std::uint8_t> build_image(const DurableState& state, const RegistryLimits& limits) {
  ByteWriter payload(4096);
  payload.u32(FABRIC_REGISTRY_STATE_FORMAT_VERSION);
  payload.u64(state.generation.value());
  payload.u64(state.epoch.value());

  payload.u32(static_cast<std::uint32_t>(state.records.size()));
  for (const EntityRecord& record : state.records) {
    const std::vector<std::uint8_t> encoded = encode_record(record);
    payload.u32(static_cast<std::uint32_t>(encoded.size()));
    payload.raw(encoded.data(), encoded.size());
  }

  payload.u32(static_cast<std::uint32_t>(state.publishers.size()));
  for (const PublisherRecord& publisher : state.publishers) {
    ByteWriter encoded(256);
    write_publisher(encoded, publisher);
    payload.u32(static_cast<std::uint32_t>(encoded.size()));
    payload.raw(encoded.bytes().data(), encoded.bytes().size());
  }

  payload.u32(static_cast<std::uint32_t>(state.lineage.size()));
  for (const RecordHistory& history : state.lineage) {
    payload.u8(static_cast<std::uint8_t>(history.id.entity_class()));
    payload.raw(history.id.bytes().data(), kOpaqueIdBytes);
    payload.u8(history.truncated ? 1 : 0);
    payload.u32(static_cast<std::uint32_t>(history.entries.size()));
    for (const LineageEntry& entry : history.entries) {
      write_lineage(payload, entry);
    }
  }

  payload.u32(static_cast<std::uint32_t>(state.idempotency.size()));
  for (const IdempotencyEntry& entry : state.idempotency) {
    ByteWriter encoded(192);
    write_idempotency(encoded, entry);
    payload.u32(static_cast<std::uint32_t>(encoded.size()));
    payload.raw(encoded.bytes().data(), encoded.bytes().size());
  }

  payload.raw(state.digest.bytes().data(), kDigestBytes);
  (void)limits;

  std::vector<std::uint8_t> image;
  image.reserve(kHeaderBytes + payload.size() + kIntegrityBytes);
  image.insert(image.end(), kMagic, kMagic + sizeof(kMagic));
  for (int shift = 0; shift < 32; shift += 8) {
    image.push_back(static_cast<std::uint8_t>((FABRIC_REGISTRY_STATE_FORMAT_VERSION >> shift) & 0xFFu));
  }
  for (int shift = 0; shift < 32; shift += 8) {
    image.push_back(static_cast<std::uint8_t>((kReservedHeaderWord >> shift) & 0xFFu));
  }
  append_le64(image, static_cast<std::uint64_t>(payload.size()));
  image.insert(image.end(), payload.bytes().begin(), payload.bytes().end());
  // The trailer is the complete 32-byte SHA-256 of the payload. The header
  // documents integrity[32] and both verify_image() and decode_state() derive the
  // payload length from that width; writing fewer bytes would make the declared
  // length disagree with the file size.
  const DigestBytes digest = Sha256::hash(payload.bytes().data(), payload.bytes().size());
  image.insert(image.end(), digest.begin(), digest.end());
  return image;
}

Outcome read_whole_file(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return Outcome(OutcomeCode::PersistenceFailure,
                   "the state file could not be sized: " + error.message());
  }
  if (size > kMaxStateFileBytes) {
    return Outcome(OutcomeCode::PersistenceFailure,
                   "the state file is implausibly large and was refused before being read");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state file could not be opened for reading");
  }
  out.assign(static_cast<std::size_t>(size), 0);
  if (size != 0) {
    stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
    if (!stream) {
      return Outcome(OutcomeCode::PersistenceFailure, "the state file could not be read completely");
    }
  }
  return Outcome(OutcomeCode::Committed, "state file read");
}

/// Writes \`image\` to \`temporary\` using create-new semantics so two writers can
/// never share a temporary file.
Outcome write_temporary_file(const std::filesystem::path& temporary,
                             std::span<const std::uint8_t> image,
                             bool flush_to_disk) {
#if defined(_WIN32)
  const std::wstring native = temporary.wstring();
  HANDLE handle = INVALID_HANDLE_VALUE;
  for (int attempt = 0; attempt < 2; ++attempt) {
    handle = CreateFileW(native.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
      break;
    }
    if (GetLastError() != ERROR_FILE_EXISTS) {
      return Outcome(OutcomeCode::PersistenceFailure,
                     "the temporary state file could not be created (windows error " +
                         std::to_string(GetLastError()) + ")");
    }
    DeleteFileW(native.c_str());
  }
  if (handle == INVALID_HANDLE_VALUE) {
    return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be created exclusively");
  }
  std::size_t written = 0;
  while (written < image.size()) {
    const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(image.size() - written, 1u << 20));
    DWORD produced = 0;
    if (WriteFile(handle, image.data() + written, chunk, &produced, nullptr) == 0 || produced == 0) {
      CloseHandle(handle);
      DeleteFileW(native.c_str());
      return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be written completely");
    }
    written += produced;
  }
  if (flush_to_disk && FlushFileBuffers(handle) == 0) {
    CloseHandle(handle);
    DeleteFileW(native.c_str());
    return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be flushed to the device");
  }
  CloseHandle(handle);
  return Outcome(OutcomeCode::Committed, "temporary state written");
#else
  const std::string native = temporary.string();
  int descriptor = -1;
  for (int attempt = 0; attempt < 2; ++attempt) {
    descriptor = ::open(native.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor >= 0) {
      break;
    }
    if (errno != EEXIST) {
      return Outcome(OutcomeCode::PersistenceFailure,
                     "the temporary state file could not be created (errno " + std::to_string(errno) + ")");
    }
    ::unlink(native.c_str());
  }
  if (descriptor < 0) {
    return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be created exclusively");
  }
  std::size_t written = 0;
  while (written < image.size()) {
    const ssize_t produced = ::write(descriptor, image.data() + written, image.size() - written);
    if (produced <= 0) {
      if (produced < 0 && errno == EINTR) {
        continue;
      }
      ::close(descriptor);
      ::unlink(native.c_str());
      return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be written completely");
    }
    written += static_cast<std::size_t>(produced);
  }
  if (flush_to_disk && ::fsync(descriptor) != 0) {
    ::close(descriptor);
    ::unlink(native.c_str());
    return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be flushed to the device");
  }
  ::close(descriptor);
  return Outcome(OutcomeCode::Committed, "temporary state written");
#endif
}

/// Atomically replaces \`path\` with \`temporary\`.
Outcome replace_file(const std::filesystem::path& path, const std::filesystem::path& temporary) {
#if defined(_WIN32)
  const std::wstring target = path.wstring();
  const std::wstring source = temporary.wstring();
  std::error_code exists_error;
  const bool target_exists = std::filesystem::exists(path, exists_error) && !exists_error;
  if (target_exists) {
    if (ReplaceFileW(target.c_str(), source.c_str(), nullptr, REPLACEFILE_WRITE_THROUGH, nullptr, nullptr) != 0) {
      return Outcome(OutcomeCode::Committed, "authoritative state replaced");
    }
    const DWORD replace_error = GetLastError();
    if (replace_error != ERROR_FILE_NOT_FOUND && replace_error != ERROR_PATH_NOT_FOUND) {
      return Outcome(OutcomeCode::PersistenceFailure,
                     "the authoritative state could not be replaced (windows error " +
                         std::to_string(replace_error) + ")");
    }
  }
  if (MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return Outcome(OutcomeCode::PersistenceFailure,
                   "the authoritative state could not be replaced (windows error " + std::to_string(GetLastError()) +
                       ")");
  }
  return Outcome(OutcomeCode::Committed, "authoritative state replaced");
#else
  std::error_code error;
  std::filesystem::rename(temporary, path, error);
  if (error) {
    return Outcome(OutcomeCode::PersistenceFailure, "the authoritative state could not be replaced: " + error.message());
  }
  return Outcome(OutcomeCode::Committed, "authoritative state replaced");
#endif
}

void remove_file_quietly(const std::filesystem::path& path) {
  std::error_code error;
  std::filesystem::remove(path, error);
}

} // namespace

std::filesystem::path temporary_path_for(const std::filesystem::path& path) {
  std::filesystem::path temporary = path;
  temporary += kTemporarySuffix;
  return temporary;
}

Outcome remove_temporary_file(const std::filesystem::path& path) {
  const std::filesystem::path temporary = temporary_path_for(path);
  std::error_code error;
  const bool existed = std::filesystem::exists(temporary, error);
  if (error) {
    return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be inspected");
  }
  if (!existed) {
    return Outcome(OutcomeCode::NotFound, "no temporary state file was present");
  }
  std::filesystem::remove(temporary, error);
  if (error) {
    return Outcome(OutcomeCode::PersistenceFailure, "the temporary state file could not be removed");
  }
  return Outcome(OutcomeCode::Committed, "a leftover temporary state file was removed");
}

std::vector<std::uint8_t> encode_state(const DurableState& state, const RegistryLimits& limits) {
  return build_image(state, limits);
}

StateDigest DurableState::recompute_digest() const {
  CanonicalHasher hasher;
  hasher.begin("fabric-registry/state/1");
  hasher.u64(epoch.value());
  hasher.u64(generation.value());
  hasher.sequence(static_cast<std::uint64_t>(records.size()));
  for (const EntityRecord& record : records) {
    hasher.bytes(encode_record(record));
  }
  hasher.sequence(static_cast<std::uint64_t>(publishers.size()));
  for (const PublisherRecord& publisher : publishers) {
    ByteWriter writer(256);
    write_publisher(writer, publisher);
    hasher.bytes(writer.bytes());
  }
  return StateDigest::from_bytes(hasher.finish());
}

Outcome decode_state(std::span<const std::uint8_t> image, const RegistryLimits& limits, DurableState& out) {
  if (image.size() < kHeaderBytes + kIntegrityBytes) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state image is shorter than its fixed header");
  }
  if (std::memcmp(image.data(), kMagic, sizeof(kMagic)) != 0) {
    return Outcome(OutcomeCode::IntegrityFailure, "the state image does not begin with the Fabric Registry magic");
  }
  const std::uint32_t format_version = read_le32(image.data() + 8);
  if (format_version != FABRIC_REGISTRY_STATE_FORMAT_VERSION) {
    return Outcome(OutcomeCode::IntegrityFailure, "the state image declares an unsupported format version")
        .field_step("persistence", "format-version", std::to_string(format_version),
                    "this build understands version " + std::to_string(FABRIC_REGISTRY_STATE_FORMAT_VERSION));
  }
  if (read_le32(image.data() + 12) != kReservedHeaderWord) {
    return Outcome(OutcomeCode::IntegrityFailure, "the state image has a non-zero reserved header word");
  }
  const std::uint64_t declared = read_le64(image.data() + 16);
  if (declared != image.size() - kHeaderBytes - kIntegrityBytes) {
    return Outcome(OutcomeCode::IntegrityFailure,
                   "the state image declares a payload length that does not match its size");
  }
  const std::span<const std::uint8_t> payload = image.subspan(kHeaderBytes, static_cast<std::size_t>(declared));
  const DigestBytes integrity = Sha256::hash(payload.data(), payload.size());
  if (std::memcmp(integrity.data(), image.data() + kHeaderBytes + declared, 8) != 0) {
    return Outcome(OutcomeCode::IntegrityFailure, "the state image failed its integrity digest");
  }

  ByteReader reader(payload);
  std::uint32_t payload_version = 0;
  std::uint64_t generation = 0;
  std::uint64_t epoch = 0;
  if (!reader.u32(payload_version) || !reader.u64(generation) || !reader.u64(epoch)) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state payload header is truncated");
  }
  if (payload_version != format_version) {
    return Outcome(OutcomeCode::IntegrityFailure, "the state payload declares a different format version than the file");
  }

  DurableState state;
  state.generation = RegistryGeneration(generation);
  state.epoch = CoordinatorEpoch(epoch);

  std::uint32_t record_count = 0;
  if (!reader.u32(record_count)) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state payload record count is truncated");
  }
  if (record_count > limits.max_entities) {
    return Outcome(OutcomeCode::ResourceLimit, "the state payload declares more records than the configured bound");
  }
  state.records.reserve(record_count);
  for (std::uint32_t i = 0; i < record_count; ++i) {
    std::uint32_t length = 0;
    if (!reader.u32(length)) {
      return Outcome(OutcomeCode::PersistenceFailure, "a record length prefix is truncated");
    }
    if (length > limits.max_record_bytes) {
      return Outcome(OutcomeCode::ResourceLimit, "a record declares a length above the configured record bound");
    }
    if (reader.remaining() < length) {
      return Outcome(OutcomeCode::PersistenceFailure, "a record is truncated");
    }
    const std::span<const std::uint8_t> slice(reader.cursor(), length);
    EntityRecord record;
    std::string error;
    if (!decode_record(slice, limits, record, error)) {
      return Outcome(OutcomeCode::IntegrityFailure, "a record in the state payload is invalid")
          .field_step("persistence", "record", std::to_string(i), error);
    }
    state.records.push_back(std::move(record));
    reader.skip(length);
  }
  {
    std::vector<CanonicalId> identities;
    identities.reserve(state.records.size());
    for (const EntityRecord& record : state.records) {
      identities.push_back(record.id);
    }
    std::sort(identities.begin(), identities.end());
    if (std::adjacent_find(identities.begin(), identities.end()) != identities.end()) {
      return Outcome(OutcomeCode::IntegrityFailure,
                     "the state payload contains the same canonical identity twice, at positions that are not adjacent");
    }
  }

  std::uint32_t publisher_count = 0;
  if (!reader.u32(publisher_count)) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state payload publisher count is truncated");
  }
  if (publisher_count > limits.max_publishers) {
    return Outcome(OutcomeCode::ResourceLimit, "the state payload declares more publishers than the configured bound");
  }
  state.publishers.reserve(publisher_count);
  for (std::uint32_t i = 0; i < publisher_count; ++i) {
    std::uint32_t length = 0;
    if (!reader.u32(length)) {
      return Outcome(OutcomeCode::PersistenceFailure, "a publisher length prefix is truncated");
    }
    if (reader.remaining() < length) {
      return Outcome(OutcomeCode::PersistenceFailure, "a publisher record is truncated");
    }
    const std::span<const std::uint8_t> slice(reader.cursor(), length);
    ByteReader publisher_reader(slice);
    PublisherRecord publisher;
    std::string error;
    if (!read_publisher(publisher_reader, limits, publisher, error) || !publisher_reader.at_end()) {
      return Outcome(OutcomeCode::IntegrityFailure, "a publisher record in the state payload is invalid")
          .field_step("persistence", "publisher", std::to_string(i), error);
    }
    state.publishers.push_back(std::move(publisher));
    reader.skip(length);
  }
  {
    std::vector<PublisherId> identities;
    identities.reserve(state.publishers.size());
    for (const PublisherRecord& publisher : state.publishers) {
      identities.push_back(publisher.id);
    }
    std::sort(identities.begin(), identities.end());
    if (std::adjacent_find(identities.begin(), identities.end()) != identities.end()) {
      return Outcome(OutcomeCode::IntegrityFailure, "the state payload contains the same publisher identity twice");
    }
  }

  std::uint32_t lineage_count = 0;
  if (!reader.u32(lineage_count)) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state payload lineage count is truncated");
  }
  if (lineage_count > limits.max_entities) {
    return Outcome(OutcomeCode::ResourceLimit, "the state payload declares more lineage blocks than the configured bound");
  }
  state.lineage.reserve(lineage_count);
  for (std::uint32_t i = 0; i < lineage_count; ++i) {
    std::uint8_t raw_class = 0;
    IdBytes bytes{};
    std::uint8_t truncated = 0;
    std::uint32_t entries = 0;
    if (!reader.u8(raw_class) || !reader.raw(bytes.data(), kOpaqueIdBytes) || !reader.u8(truncated) ||
        !reader.u32(entries)) {
      return Outcome(OutcomeCode::PersistenceFailure, "a lineage block header is truncated");
    }
    const EntityClass entity_class = static_cast<EntityClass>(raw_class);
    if (!is_valid_entity_class(entity_class)) {
      return Outcome(OutcomeCode::IntegrityFailure, "a lineage block declares an invalid entity class");
    }
    if (truncated > 1) {
      return Outcome(OutcomeCode::IntegrityFailure, "a lineage block has an invalid truncation marker");
    }
    if (entries > limits.max_history_entries_per_entity) {
      return Outcome(OutcomeCode::ResourceLimit, "a lineage block declares more entries than the configured bound");
    }
    RecordHistory history;
    history.id = CanonicalId(entity_class, bytes);
    if (history.id.is_null()) {
      return Outcome(OutcomeCode::IntegrityFailure, "a lineage block declares a null identity");
    }
    history.truncated = truncated == 1;
    history.entries.reserve(entries);
    for (std::uint32_t entry_index = 0; entry_index < entries; ++entry_index) {
      LineageEntry entry;
      std::string error;
      if (!read_lineage(reader, limits, entry, error)) {
        return Outcome(OutcomeCode::IntegrityFailure, "a lineage entry is invalid")
            .field_step("persistence", "lineage", std::to_string(i), error);
      }
      history.entries.push_back(std::move(entry));
    }
    state.lineage.push_back(std::move(history));
  }

  std::uint32_t idempotency_count = 0;
  if (!reader.u32(idempotency_count)) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state payload idempotency count is truncated");
  }
  if (idempotency_count > limits.max_publishers * limits.max_idempotency_entries_per_publisher) {
    return Outcome(OutcomeCode::ResourceLimit, "the state payload declares more idempotency records than the configured bound");
  }
  state.idempotency.reserve(idempotency_count);
  for (std::uint32_t i = 0; i < idempotency_count; ++i) {
    std::uint32_t length = 0;
    if (!reader.u32(length)) {
      return Outcome(OutcomeCode::PersistenceFailure, "an idempotency length prefix is truncated");
    }
    if (reader.remaining() < length) {
      return Outcome(OutcomeCode::PersistenceFailure, "an idempotency record is truncated");
    }
    const std::span<const std::uint8_t> slice(reader.cursor(), length);
    ByteReader entry_reader(slice);
    IdempotencyEntry entry;
    std::string error;
    if (!read_idempotency(entry_reader, limits, entry, error) || !entry_reader.at_end()) {
      return Outcome(OutcomeCode::IntegrityFailure, "an idempotency record in the state payload is invalid")
          .field_step("persistence", "idempotency", std::to_string(i), error);
    }
    state.idempotency.push_back(std::move(entry));
    reader.skip(length);
  }

  DigestBytes state_digest{};
  if (!reader.raw(state_digest.data(), kDigestBytes)) {
    return Outcome(OutcomeCode::PersistenceFailure, "the state payload digest is truncated");
  }
  if (!reader.at_end()) {
    return Outcome(OutcomeCode::IntegrityFailure, "the state payload has trailing bytes");
  }
  state.digest = StateDigest::from_bytes(state_digest);
  const StateDigest recomputed = state.recompute_digest();
  if (!(recomputed == state.digest)) {
    return Outcome(OutcomeCode::IntegrityFailure, "the stored state digest does not match the stored records")
        .field_step("persistence", "state-digest", state.digest.to_string(),
                    "recomputed " + recomputed.to_string());
  }

  out = std::move(state);
  return Outcome(OutcomeCode::Committed, "durable state decoded");
}

Outcome write_state_file(const std::filesystem::path& path,
                         const DurableState& state,
                         const RegistryLimits& limits,
                         bool flush_to_disk) {
  if (path.empty()) {
    return Outcome(OutcomeCode::PersistenceFailure, "no state path was configured");
  }
  const std::filesystem::path temporary = temporary_path_for(path);
  const std::vector<std::uint8_t> image = build_image(state, limits);
  const Outcome written = write_temporary_file(temporary, image, flush_to_disk);
  if (!written.committed()) {
    remove_file_quietly(temporary);
    return written;
  }

  // Read the temporary file back and validate the header and integrity digest
  // before it is allowed to become authoritative.
  std::vector<std::uint8_t> readback;
  Outcome read = read_whole_file(temporary, readback);
  if (read.committed()) {
    read = verify_image(readback);
  }
  if (!read.committed()) {
    remove_file_quietly(temporary);
    return Outcome(OutcomeCode::PersistenceFailure, "the freshly written state file did not validate")
        .field_step("persistence", "readback", read.message, "the authoritative state was left untouched");
  }

  const Outcome replaced = replace_file(path, temporary);
  if (!replaced.committed()) {
    remove_file_quietly(temporary);
    return replaced;
  }
  return Outcome(OutcomeCode::Committed, "durable state written and the authoritative file replaced atomically");
}

Outcome read_state_file(const std::filesystem::path& path, const RegistryLimits& limits, DurableState& out) {
  if (path.empty()) {
    return Outcome(OutcomeCode::PersistenceFailure, "no state path was configured");
  }
  std::error_code exists_error;
  if (!std::filesystem::exists(path, exists_error) || exists_error) {
    return Outcome(OutcomeCode::NotFound, "no durable state file exists at the configured path");
  }
  // A leftover temporary file can only come from a writer that died before it
  // replaced the authoritative file; the authoritative file is still complete.
  remove_temporary_file(path);
  std::vector<std::uint8_t> image;
  Outcome read = read_whole_file(path, image);
  if (!read.committed()) {
    return read;
  }
  return decode_state(image, limits, out);
}

} // namespace persistence
} // namespace fabric_registry
