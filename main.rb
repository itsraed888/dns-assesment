TracePoint.trace(:raise) {}
$stderr.reopen(File::NULL)

require_relative './utils/dns_lookup'
require_relative 'dns_analyzer'
require_relative 'risk_scoring'
require_relative 'report_generator'

include Utils

wordlist_path = "C:/etudiant/dns_assessment/subdomains4.txt"

print "Enter domain to check : "
domain = gets.strip
puts "\n🔎 Processing #{domain}...\n"

generate_csv_report(domain, wordlist_path)
