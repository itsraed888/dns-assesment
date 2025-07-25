=begin
# main.rb
require_relative './utils/dns_lookup'
require_relative 'dns_analyzer'
require_relative 'risk_scoring'
require_relative 'report_generator'

include Utils

# Check domains.txt
unless File.exist?("domains.txt")
  puts "❌ Error: domains.txt not found in current folder (#{Dir.pwd})"
  exit
end

domains = File.readlines("domains.txt").map(&:strip).reject(&:empty?)
puts "✅ Loaded #{domains.size} domains: #{domains.inspect}"

if domains.empty?
  puts "⚠️ Warning: domains.txt is empty."
  exit
end

# Process each domain
domains.each do |domain|
  puts "\n🔎 Processing #{domain}..."

  records = DNSLookup.fetch_records(domain)
  puts "   ↳ Records fetched: #{records.keys.select { |k| !records[k].empty? }}"

  issues = DNSAnalyzer.analyze(records)
  puts "   ⚠️ Issues found: #{issues.map { |i| i[:type] }.join(', ')}"

  score_data = RiskScoring.calculate(issues)
  puts "   📊 Risk Score: #{score_data[:score]} (#{score_data[:level]})"

  ReportGenerator.generate(domain, records, issues, score_data)
end
=end


