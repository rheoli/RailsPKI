desc 'RailsPKI CA CRL'
 
task "railspki:ca:crl" => :environment do
  ActiveRecord::Base.establish_connection

  crls=Hash.new
  CaDomain.find(:all).each do |ca|
    name=ca.dn["CN"].gsub!(/ /, '_').downcase!
    crl_old=nil
    if File.exists?("config/ssl/crls/#{name}.crl")
      crl_old=OpenSSL::X509::CRL.new(File.open("config/ssl/crls/#{name}.crl", "r"))
    end
    version=1
    last_update=Time.now
    if !crl_old.nil?
      version=crl_old.version+1
      last_update=crl_old.last_update
    end
    crl=OpenSSL::X509::CRL.new
    crl.issuer =ca.pubkey.subject
    crl.version=version
    crl.last_update = Time.now #last_update
    crl.next_update = Time.now.to_i+100000
    crls[ca.id.to_s]=[crl, ca, name]
  end
  
  print "Find revoked certs..."
  CaRevoke.find(:all).each do |rev|
    ca_id=rev.ca_item.ca_domain.id
    revoked=OpenSSL::X509::Revoked.new
    revoked.serial=rev.ca_item.crt_serial.to_i
    revoked.time  =rev.created_on
    ext = OpenSSL::X509::Extension.new("CRLReason", rev.reason)
    revoked.add_extension(ext)
    crls[ca_id.to_s][0].add_revoked(revoked)
  end
  print "done\n"
  
  crls.each do |id, crl|
    ca=crl[1]
    print "Generate CRL for #{crl[2]}"
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = ca.pubkey
    ef.crl = crl[0]
    crlnum = OpenSSL::ASN1::Integer(1)
    crl[0].add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
    #extensions.each{|oid, value, critical|
    #  crl.add_extension(ef.create_extension(oid, value, critical))
    #}
    crl[0].sign(ca.privkey, OpenSSL::Digest::SHA1.new)
    File.open("config/ssl/crls/#{crl[2]}.crl", "w") do |f|
      f.write(crl[0].to_pem)
    end
    print "done\n"
  end


end
