#!/usr/bin/env ruby

require "yaml"

class OpenAPIError < StandardError; end

def load_document(path, documents)
  path = File.expand_path(path)
  documents[path] ||= YAML.safe_load(File.read(path))
rescue Errno::ENOENT, Psych::Exception => error
  raise OpenAPIError, "cannot load #{path}: #{error.message}"
end

def resolve_reference(reference, path, documents)
  file, pointer = reference.split("#", 2)
  document_path = file.empty? ? path : File.expand_path(file, File.dirname(path))
  value = load_document(document_path, documents)
  return [document_path, "", value] if pointer.nil? || pointer.empty?
  raise OpenAPIError, "invalid local reference #{reference.inspect}" unless pointer.start_with?("/")

  pointer.split("/")[1..].each do |part|
    part = part.gsub("~1", "/").gsub("~0", "~")
    value = case value
            when Hash then value.fetch(part) { raise OpenAPIError, "unresolved local reference #{reference.inspect}" }
            when Array then value.fetch(Integer(part, 10)) { raise OpenAPIError, "unresolved local reference #{reference.inspect}" }
            else raise OpenAPIError, "unresolved local reference #{reference.inspect}"
            end
  end
  [document_path, pointer, value]
rescue ArgumentError, IndexError
  raise OpenAPIError, "unresolved local reference #{reference.inspect}"
end

def local_reference?(reference)
  reference.start_with?("#") || reference !~ %r{^(?:[a-z][a-z0-9+.-]*:|//)}i
end

def resolve_local_references(value, path, documents, seen = {})
  case value
  when Hash
    reference = value["$ref"]
    if reference
      raise OpenAPIError, "$ref must be a string" unless reference.is_a?(String)
      if local_reference?(reference)
        target_path, pointer, target = resolve_reference(reference, path, documents)
        key = [target_path, pointer]
        unless seen[key]
          seen[key] = true
          resolve_local_references(target, target_path, documents, seen)
        end
      end
    end
    value.each_value { |child| resolve_local_references(child, path, documents, seen) }
  when Array
    value.each { |child| resolve_local_references(child, path, documents, seen) }
  end
end

def require_value(value, expected, name)
  raise OpenAPIError, "#{name}=#{value.inspect}, want #{expected.inspect}" unless value == expected
end

document_path = File.expand_path("../docs/openapi.yaml", __dir__)
documents = {}
document = load_document(document_path, documents)
resolve_local_references(document, document_path, documents)

upload = document.dig("paths", "/v1/scip/uploads", "post", "requestBody", "content", "application/vnd.scip+protobuf", "schema")
graph_upload = document.dig("paths", "/v1/graph/uploads", "post", "requestBody", "content", "application/vnd.grepnest.graph.v1+protobuf", "schema")
graph_status = document.dig("paths", "/v1/graph/repositories/{id}/status", "get", "responses", "200", "content", "application/json", "schema")
graph_queries = %w[context impact trace cypher].to_h do |name|
  [name, document.dig("paths", "/v1/graph/#{name}", "post")]
end
locations = document.dig("components", "schemas", "SCIPNavigationResponse", "properties", "locations")
raise OpenAPIError, "SCIP upload schema is missing" unless upload.is_a?(Hash)
raise OpenAPIError, "graph upload schema is missing" unless graph_upload.is_a?(Hash)
raise OpenAPIError, "graph status schema is missing" unless graph_status.is_a?(Hash)
raise OpenAPIError, "graph query routes are missing" unless graph_queries.values.all? { |query| query.is_a?(Hash) }
raise OpenAPIError, "SCIP navigation locations schema is missing" unless locations.is_a?(Hash)

require_value(upload["x-default-max-bytes"], 67_108_864, "SCIP upload default byte cap")
require_value(upload["x-server-max-bytes"], 268_435_456, "SCIP upload server byte cap")
require_value(graph_upload["x-default-max-bytes"], 67_108_864, "graph upload default byte cap")
require_value(graph_upload["x-server-max-bytes"], 268_435_456, "graph upload server byte cap")
require_value(graph_status["$ref"], "#/components/schemas/GraphStatus", "graph status response schema")
require_value(locations["maxItems"], 100, "SCIP navigation locations cap")
graph_queries.each do |name, query|
  schema = query.dig("requestBody", "content", "application/json", "schema")
  response = query.dig("responses", "200", "content", "application/json", "schema")
  raise OpenAPIError, "graph #{name} request schema is missing" unless schema.is_a?(Hash)
  raise OpenAPIError, "graph #{name} response schema is missing" unless response.is_a?(Hash)
  require_value(schema["$ref"], "#/components/schemas/Graph#{name.capitalize}Request", "graph #{name} request schema")
  require_value(response["$ref"], "#/components/schemas/Graph#{name.capitalize}Response", "graph #{name} response schema")
  raise OpenAPIError, "graph #{name} timeout response is missing" unless query.dig("responses", "504").is_a?(Hash)
end
raise OpenAPIError, "graph cypher forbidden response is missing" unless graph_queries.fetch("cypher").dig("responses", "403").is_a?(Hash)

schemas = document.fetch("components").fetch("schemas")
audit_event = schemas.fetch("AuditEvent").fetch("properties")
raise OpenAPIError, "AuditEvent.authentication_method omits oauth" unless audit_event.fetch("authentication_method").fetch("enum").include?("oauth")
%w[oauth_login_succeeded oauth_login_denied].each do |operation|
  raise OpenAPIError, "AuditEvent.operation omits #{operation}" unless audit_event.fetch("operation").fetch("enum").include?(operation)
end
auth_config = schemas.fetch("AuthConfig")
raise OpenAPIError, "AuthConfig must require file_reads" unless auth_config.fetch("required").include?("file_reads")
require_value(auth_config.dig("properties", "file_reads", "type"), "boolean", "AuthConfig.file_reads type")
candidate = schemas.fetch("GraphCandidate")
raise OpenAPIError, "GraphCandidate must require repository_id" unless candidate.fetch("required").include?("repository_id")
require_value(candidate.dig("properties", "repository_id", "minimum"), 1, "GraphCandidate.repository_id minimum")
{
  "GraphContextResponse" => %w[found not_found ambiguous],
  "GraphImpactResponse" => %w[found not_found ambiguous],
  "GraphTraceResponse" => %w[ok no_path ambiguous]
}.each do |name, statuses|
  schema = schemas.fetch(name)
  variants = schema["oneOf"]
  raise OpenAPIError, "#{name} is not discriminated" unless variants.is_a?(Array) && variants.length == statuses.length
  require_value(schema.dig("discriminator", "propertyName"), "status", "#{name} discriminator")
  statuses.each do |status|
    suffix = status == "ok" ? "OK" : status.split("_").map(&:capitalize).join
    variant = variants.find { |value| value["$ref"] == "#/components/schemas/#{name.sub("Response", "")}#{suffix}Response" }
    raise OpenAPIError, "#{name} #{status} variant is missing" unless variant
    resolved = schemas.fetch(variant["$ref"].split("/").last)
    require_value(resolved.dig("properties", "status", "const"), status, "#{name} #{status} status")
    raise OpenAPIError, "#{name} #{status} variant permits unknown fields" unless resolved["additionalProperties"] == false
  end
end

{
  ["GraphContextResponse", "found"] => "symbol",
  ["GraphContextResponse", "ambiguous"] => "candidates",
  ["GraphImpactResponse", "ambiguous"] => "candidates",
  ["GraphTraceResponse", "ok"] => "nodes",
  ["GraphTraceResponse", "ambiguous"] => "candidates"
}.each do |(name, status), field|
  suffix = status == "ok" ? "OK" : status.split("_").map(&:capitalize).join
  variant_name = "#{name.sub("Response", "")}#{suffix}Response"
  variant = schemas.fetch(variant_name)
  raise OpenAPIError, "#{variant_name} must require #{field}" unless variant.fetch("required").include?(field)
  items = variant.dig("properties", field)
  require_value(items["minItems"], 1, "#{variant_name} #{field} minimum") if %w[candidates nodes].include?(field)
end

{
  ["GraphImpactRequest", "max_depth"] => [3, 32],
  ["GraphTraceRequest", "max_depth"] => [10, 30],
  ["GraphContextRequest", "per_category_limit"] => [100, 100],
  ["GraphImpactRequest", "limit"] => [100, 100],
  ["GraphCypherRequest", "max_rows"] => [100, 100],
  ["GraphCypherRequest", "max_bytes"] => [262_144, 262_144]
}.each do |(schema_name, property_name), (default, cap)|
  property = schemas.fetch(schema_name).fetch("properties").fetch(property_name)
  require_value(property["default"], default, "#{schema_name}.#{property_name} default") unless default.nil?
  raise OpenAPIError, "#{schema_name}.#{property_name} falsely rejects capped values" if property.key?("maximum")
  raise OpenAPIError, "#{schema_name}.#{property_name} cap is undocumented" unless property.fetch("description", "").include?(cap.to_s)
end

puts "OpenAPI validation passed"
