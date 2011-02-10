desc 'RailsPKI CA Sign'

require 'net/https'
require 'uri'
 
task "railspki:ca:sign" => :environment do
  ActiveRecord::Base.establish_connection

  @ca_items=CaItem.find_all_by_state(CaItem::STATE_SIGN_APPROVED)
  @ca_items.each do |item|
    item.sign_and_save
  end

  log=[]
  RaServer.find_all.each do |rs|
    if rs.name=="-local-"
      CaItem.find(:all, :conditions=>["state like ? and ra_server_id=?", CaItem::STATE_SIGNED, rs.id]).each do |ci|
        if RaItem.update_ra_item(ci)!=nil
          log<<"#{rs.name}: #{ci.dn} updated"
          ci.state=CaItem::STATE_RA_SYNCED
          ci.save
        end
      end
    end
  end
end
