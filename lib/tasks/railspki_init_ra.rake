desc 'Init RailsPKI RA Instance'

task "railspki:init_ra" => :environment do
  ActiveRecord::Base.establish_connection
  
  print "Tag Instance as RA_INSTANCE...\n"
  print "Please input the CA instance IP address: "
  ca_ip=STDIN.gets.chomp
  inst=PKIInstance.new
  inst.name="RailsPKI RA"
  inst.instance=PKIInstance::RA_INSTANCE
  inst.ca_instance_ip=ca_ip
  inst.save
  print "done\n"
end