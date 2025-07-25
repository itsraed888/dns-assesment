require_relative './utils/dns_lookup'
require_relative 'dns_analyzer'
require_relative 'risk_scoring'
require_relative 'report_generator'

include Utils

wordlist_path = "C:/etudiant/dns_assessment/subdomains4.txt"


print "Enter domain to check : "
domain = gets.strip
puts "\n🔎 Processing #{domain}..."

spf_result = check_spf(domain)
puts "SPF Check Result: #{spf_result}"

dmarc_result = check_dmarc(domain)
puts "DMARC Check Result: #{dmarc_result}"

#open_zone_transfer_result = check_zone_transfer(domain)
#puts "Open Zone Transfer Check Result: #{open_zone_transfer_result}"

result = dnssec_missing?(domain)
puts "DNSSEC Missing Check Result: #{result}"


=begin
def try_zone_transfer(domain, ns)
  command = "dig +short AXFR #{domain} @#{ns}"
  output = `#{command}`.strip
  if output.empty?
    puts "Zone transfer denied or no data returned from #{ns} for #{domain}"
    return nil
  else
    puts "Zone transfer data from #{ns} for #{domain}:"
    puts output
    return output
  end
end






try_zone_transfer("google.com", "ns1.google.com")
try_zone_transfer("zonetransfer.me", "nsztm1.digi.ninja")
=end

results = check_domains_from_file(domain, wordlist_path)
results.each do |cname, exists|
  puts "#{cname} => #{exists ? 'RESOLVES' : 'DOES NOT RESOLVE'}"
end



check_ttl(domain)

ptr_result = check_ptr(domain)
puts "PTR Record Check Result: #{ptr_result}"