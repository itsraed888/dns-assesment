require 'resolv'
require 'dnsruby'

$DEBUG = true
$wordlist_path = "C:/etudiant/dns_assessment/subdomains4.txt"
# func1 : spf
def check_spf(domain)
  resolver = Resolv::DNS.new(nameserver: ['8.8.8.8', '8.8.4.4'])
  begin
    resources = resolver.getresources(domain, Resolv::DNS::Resource::IN::TXT)
    resources.each do |rdata|
      txt_str = rdata.data.force_encoding('UTF-8')
      return true if txt_str[0,6].downcase == 'v=spf1'
    end
    false
  rescue => e
    puts "Error: #{e.message}"
    false
  ensure
    resolver.close
  end
end


 #------------------------------------------------------------------------------------------------------------------------ 
 #------------------------------------------------------------------------------------------------------------------------ 

# func2 : dmarc
def check_dmarc(domain)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w")
  resolver = Resolv::DNS.new(nameserver: ['8.8.8.8', '8.8.4.4'])
  dmarc_domain = "_dmarc.#{domain}"
  begin
    resources = resolver.getresources(dmarc_domain, Resolv::DNS::Resource::IN::TXT)
    resources.each do |rdata|
      txt_str = rdata.data.force_encoding('UTF-8')
      if txt_str[0,8].casecmp?('v=DMARC1')
        $stderr.close
        $stderr = original_stderr
        return true
      end
    end
    $stderr.close
    $stderr = original_stderr
    return false
  rescue => e
    puts "Error: #{e.message}"
    $stderr.close
    $stderr = original_stderr
    return false
  ensure
    resolver.close
  end
end

 #------------------------------------------------------------------------------------------------------------------------ 
 #------------------------------------------------------------------------------------------------------------------------ 

#func 3 : open zone transfer 

def check_zone_transfer(domain)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w") # Suppress stderr

  nameservers = Resolv::DNS.open do |dns|
    dns.getresources(domain, Resolv::DNS::Resource::IN::NS).map(&:name).map(&:to_s)
  end

  result = nameservers.any? do |ns|
    # debug output (remove if you want no output)
    # puts "Checking zone transfer on #{ns}"
    zone_data = `dig AXFR #{domain} @#{ns} +short`
    !zone_data.strip.empty?
  end

  $stderr.close
  $stderr = original_stderr 

  result
end


 #------------------------------------------------------------------------------------------------------------------------ 
 #------------------------------------------------------------------------------------------------------------------------ 


# func4 : dnssec

def dnssec_missing?(domain)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w") # Suppress stderr

  begin
    resolver = Dnsruby::Resolver.new
    response = resolver.query(domain, Dnsruby::Types::DNSKEY)

    if response.answer.empty?
      return true  # DNSSEC is missing
    else
      return false # DNSSEC is present
    end
  rescue => e
    puts "Could not verify DNSSEC for #{domain}: #{e.message}"
    return nil     # DNSSEC status unknown (query failed)
  ensure
    $stderr.close
    $stderr = original_stderr
  end
end


 #------------------------------------------------------------------------------------------------------------------------ 
 #------------------------------------------------------------------------------------------------------------------------ 

#func 5 : wildcard dns


def find_subdomains(domain, wordlist_path)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w")
  subdomains = []
  resolver = Resolv::DNS.new(nameserver: ['8.8.8.8', '8.8.4.4'], search: [])

  File.foreach(wordlist_path) do |word|
    sub = "#{word.strip}.#{domain}"
    begin
      resolver.getaddress(sub)
      subdomains << sub
    rescue Resolv::ResolvError
      # skip unresolved
    end
  end

  $stderr.close
  $stderr = original_stderr

  subdomains
end

 

def get_cname_targets(domain, wordlist_path)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w")
  subdomains = find_subdomains(domain, wordlist_path)
  resolver = Resolv::DNS.new(nameserver: ['8.8.8.8', '8.8.4.4'], search: [])

  cname_targets = []

  subdomains.each do |sub|
    begin
      cname = resolver.getresources(sub, Resolv::DNS::Resource::IN::CNAME).first
      cname_targets << cname.name.to_s if cname
    rescue Resolv::ResolvError
      next
    end
  end
  $stderr.close
  $stderr = original_stderr
  cname_targets
end


def check_domains_from_file(domain, wordlist_path)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w")
  domains = get_cname_targets(domain, wordlist_path)

  resolver = Resolv::DNS.new
  results = {}

  domains.each do |d|
    next if d.strip.empty?

    begin
      resolver.getaddress(d)
      results[d] = true
    rescue Resolv::ResolvError
      results[d] = false
    end
  end
  $stderr.close
  $stderr = original_stderr
  results
end



#------------------------------------------------------------------------------------------------------------------------ 
#------------------------------------------------------------------------------------------------------------------------ 

#func 6 : ttl 

def check_ttl(domain)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w")
  resolver = Dnsruby::Resolver.new
  begin
    response = resolver.query(domain, Dnsruby::Types.A)
    ttls = response.answer.select { |r| r.type == 'A' }.map(&:ttl)
    return "No A records found" if ttls.empty?

    ttls.each do |ttl|
      if ttl < 300
        puts "Low TTL detected: #{ttl} seconds (less than 5 minutes)"
      elsif ttl > 86400
        puts "High TTL detected: #{ttl} seconds (more than 1 day)"
      else
        puts "Normal TTL: #{ttl} seconds"
      end
    end
  rescue Dnsruby::NXDomain
    puts "Domain not found"
  rescue => e
    puts "Error: #{e.message}"
  end
  $stderr.close
  $stderr = original_stderr
end


#------------------------------------------------------------------------------------------------------------------------ 
#------------------------------------------------------------------------------------------------------------------------ 

#func 7 : ptr record

def check_ptr(domain)
  original_stderr = $stderr
  $stderr = File.open(File::NULL, "w")
  begin
    ip = Resolv.getaddress(domain)
    hostname = Resolv.getname(ip)

    # Check if PTR hostname matches or includes the domain
    if hostname.include?(domain)
      puts "✅ PTR Record exists and matches: #{hostname}"
      true
    else
      puts "⚠️ PTR Record exists but does NOT match: #{hostname}"
      false
    end
  rescue Resolv::ResolvError => e
    puts "❌ PTR Record missing or IP resolution failed: #{e.message}"
    false
  end
  $stderr.close
  $stderr = original_stderr
end
#dig AXFR zonetransfer.me @nsztm1.digi.ninja
#vulnerable dns for testing zone transfer 




