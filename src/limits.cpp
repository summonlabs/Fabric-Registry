// Fabric Registry — resource bounds.
//
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "fabric_registry/limits.hpp"

namespace fabric_registry {
namespace {

/// Formats "<field> must be at least <min>" style messages without pulling in a
/// formatting dependency.
std::string bound_message(std::string_view field, std::size_t value, std::size_t low, std::size_t high) {
  std::string message(field);
  message += " is out of range: ";
  message += std::to_string(value);
  message += " is not within [";
  message += std::to_string(low);
  message += ", ";
  message += std::to_string(high);
  message += "]";
  return message;
}

ValidationResult check(std::string_view field, std::size_t value, std::size_t low, std::size_t high) {
  if (value < low || value > high) {
    return ValidationResult::failure(bound_message(field, value, low, high));
  }
  return ValidationResult::success();
}

} // namespace

ValidationResult RegistryLimits::validate() const {
  ValidationResult result = check("max_entities", max_entities, 1, hard_limits::kMaxEntities);
  if (!result) {
    return result;
  }
  result = check("max_alias_entries", max_alias_entries, 1, hard_limits::kMaxAliasEntries);
  if (!result) {
    return result;
  }
  result = check("max_facts_per_entity", max_facts_per_entity, 1, hard_limits::kMaxFactsPerEntity);
  if (!result) {
    return result;
  }
  result = check("max_aliases_per_entity", max_aliases_per_entity, 1, hard_limits::kMaxAliasesPerEntity);
  if (!result) {
    return result;
  }
  result = check("max_metadata_entries", max_metadata_entries, 0, hard_limits::kMaxMetadataEntries);
  if (!result) {
    return result;
  }
  result = check("max_string_bytes", max_string_bytes, 16, hard_limits::kMaxStringBytes);
  if (!result) {
    return result;
  }
  result = check("max_metadata_value_bytes", max_metadata_value_bytes, 1, hard_limits::kMaxMetadataValueBytes);
  if (!result) {
    return result;
  }
  if (max_metadata_bytes_per_entity < max_metadata_value_bytes) {
    return ValidationResult::failure(
        "max_metadata_bytes_per_entity must be at least max_metadata_value_bytes");
  }
  result = check("max_metadata_bytes_per_entity", max_metadata_bytes_per_entity, 1,
                 hard_limits::kMaxMetadataBytesPerEntity);
  if (!result) {
    return result;
  }
  result = check("max_record_bytes", max_record_bytes, 256, hard_limits::kMaxRecordBytes);
  if (!result) {
    return result;
  }
  result = check("max_batch_size", max_batch_size, 1, hard_limits::kMaxBatchSize);
  if (!result) {
    return result;
  }
  result = check("max_idempotency_entries_per_publisher", max_idempotency_entries_per_publisher, 1,
                 hard_limits::kMaxIdempotencyEntriesPerPublisher);
  if (!result) {
    return result;
  }
  result = check("max_history_entries_per_entity", max_history_entries_per_entity, 0,
                 hard_limits::kMaxHistoryEntriesPerEntity);
  if (!result) {
    return result;
  }
  result = check("max_fenced_boots_per_publisher", max_fenced_boots_per_publisher, 1,
                 hard_limits::kMaxFencedBootsPerPublisher);
  if (!result) {
    return result;
  }
  result = check("max_publishers", max_publishers, 1, hard_limits::kMaxPublishers);
  if (!result) {
    return result;
  }
  result = check("max_history_query", max_history_query, 1, hard_limits::kMaxHistoryEntriesPerEntity);
  if (!result) {
    return result;
  }
  result = check("max_enumeration", max_enumeration, 1, hard_limits::kMaxEntities);
  if (!result) {
    return result;
  }
  return ValidationResult::success();
}

ValidationResult FrameLimits::validate() const {
  ValidationResult result = check("max_payload_bytes", max_payload_bytes, 64, hard_limits::kMaxFramePayloadBytes);
  if (!result) {
    return result;
  }
  result = check("max_pending_frames", max_pending_frames, 1, hard_limits::kMaxPendingWorkItems);
  if (!result) {
    return result;
  }
  result = check("max_sessions", max_sessions, 1, hard_limits::kMaxSessions);
  if (!result) {
    return result;
  }
  result = check("worker_threads", worker_threads, 1, hard_limits::kMaxWorkerThreads);
  if (!result) {
    return result;
  }
  return ValidationResult::success();
}

} // namespace fabric_registry
