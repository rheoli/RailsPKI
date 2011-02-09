desc 'Create CA User for RailsPKI'

task "railspki:create_ca_user" => :environment do
  ActiveRecord::Base.establish_connection
  
  print "Create an CA User...\n"
  
  inst=PKIInstance.find_by_instance(PKIInstance::CA_INSTANCE)
  if inst.nil?
    print " -> Error no CA !!!\n"
    exit
  end

  print " Enter user name: "
  ca_user=STDIN.gets.chomp
  print " Enter full name: "
  ca_full=STDIN.gets.chomp
  print " Enter password: "
  ca_passwd=STDIN.gets.chomp
  print " Enter user e-mail: "
  ca_email=STDIN.gets.chomp
  print " Choose role (1=ca_admin, 2=ca_cert_mgr): "
  ca_role_nr=STDIN.gets.to_i
  ca_role=Role::ROLE_CA_CERT_MGR
  ca_role=Role::ROLE_CA_ADMIN if ca_role_nr==1
  print " Choose auth method:\n"
  AuthMethod.find_all.each do |m|
    next if m.meth[:type]!="client_cert"
    print "  #{m.id} = #{m.name}\n"
  end
  ca_auth_meth=STDIN.gets.to_i
  ca_domain=0
  ra_server=RaServer.find_by_name("-local-").id
  if ca_role==Role::ROLE_CA_CERT_MGR
    print " Choose allowed CA Domains:\n"
    print "  0 = any\n"
    CaDomain.find_all.each do |d|
      print "  #{d.id} = #{d.name}\n"
    end
    ca_domain=STDIN.gets.to_i
  end

  print " - Find role..."
  r=Role.find(:first, :conditions=>["name like ? and ca_domain_id=? and ra_server_id=?", ca_role, ca_domain, ra_server])
  if r.nil?
    print "role not found\n"
    print " - Create new role..."
    r=Role.new
    r.name=ca_role
    r.ca_domain_id=ca_domain
    r.ra_server_id=ra_server
    r.auth_methods<<AuthMethod.find_by_id(ca_auth_meth)
    r.save
    print "done\n"
  else
    print "role found\n"
  end
  
  print " - Insert new user #{ca_user}..."
  u=User.new
  u.username=ca_user
  u.email=ca_email
  u.password="*"
  u.roles << r
  u.save
  print "done\n"
  
  print " - Generate client cert..."
  ra_req = RaReqgen.new
  ca=CaDomain.find_by_name("Rails PKI Client CA")
  params={
    "CN"=>ca_full,
    "UID"=>ca_user,
    "emailAddress"=>ca_email,
    "OU"=>"CA", "bits"=>"2048",
    "password"=>ca_passwd,
    "password_confirmation"=>ca_passwd
  }
  ra_req.add_params(ca.id, params)
  if ra_req.valid?
    c_pkey, c_req = ra_req.gen_request
    params.delete("bits")
    params.delete("password")
    params.delete("password_confirmation")
    ra_item=RaItem.new(:ca_domain_id=>ca.id, :csr=>c_req.to_pem)
    ra_item.dn=params
    ra_item.save
    ca_item=CaItem.create_from_ra_item(0, ra_item)
    ca_item.sign_and_save
    ra_item_n=RaItem.update_ra_item(ca_item)
    p12=OpenSSL::PKCS12.create(ca_passwd, "Rails PKI Client Cert for #{ca_full}",
         OpenSSL::PKey::RSA.new(c_pkey),
         OpenSSL::X509::Certificate.new(ra_item_n.crt_pem),
         [OpenSSL::X509::Certificate.new(ca.pubkey_pem),
          OpenSSL::X509::Certificate.new(ca.ca_domain.pubkey_pem),
          OpenSSL::X509::Certificate.new(ca.ca_domain.ca_domain.pubkey_pem)])
    File.open("config/ssl/users/#{ca_user}.p12", "w") do |f|
      f.write(p12.to_der)
    end
    File.open("config/ssl/users/#{ca_user}.key", "w") do |f|
      f.write(c_pkey)
    end
    File.open("config/ssl/users/#{ca_user}.crt", "w") do |f|
      f.write(ra_item_n.crt_pem)
    end
  else
    p ra_req
    print " -> Error to create cert\n"
    exit(1)
  end
  print "done\n"
end
