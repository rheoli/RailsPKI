desc 'RailsPKI CA Sign'

require 'net/https'
require 'uri'
 
task "railspki:ca:sign" => :environment do
  ActiveRecord::Base.establish_connection
  ActionWebService::API::Base.allow_active_record_expects=true

  @ca_items=CaItem.find_in_state(:all, :ready_to_sign)
  @ca_items.each do |item|
    item.sign_and_save
  end

  log=[]
  RaServer.find(:all).each do |rs|
    ca_items=CaItem.find_in_state(:all, :signed, :conditions=>["ra_server_id=?", rs.id])
    if rs.name=="-local-"
      ca_items.each do |ci|
        if RaItem.update_ra_item(ci)!=nil
          log<<"#{rs.name}: #{ci.dn} updated"
          ci.synced!
          ci.save
        end
      end
    else
      server=rs.ca_item.dn["CN"]
      o=ActionWebService::Client::Soap.new(BackendApi, "https://#{server}/pki/backend/api")
      begin
        ca_items.each do |ci|
          yaml=ci.export_yaml
          if o.update_ra_item(yaml)!=nil
            log<<"#{rs.name}: #{ci.dn} updated"
            ci.synced!
            ci.save
          end
        end
      rescue
        print "Can't connect to #{server}\n"
      end
    end
  end
end
