desc 'RailsPKI RA Expire'

require 'net/https'
require 'uri'
 
task "railspki:ra:expire" => :environment do
  ActiveRecord::Base.establish_connection

  t=Time.now
  ra_items=RaItem.find(:all, :conditions=>["crt_end > ? and crt_end < ?", t-(31*3600*24), t])
  ra_items.each do |ra|
    days=(ra.crt_end-t).to_i/24/3600
    if days%10==0
      print "#{ra["dn"]["CN"]} expires in #{(ra.crt_end-t).to_i/24/3600} days\n"
    end
    #o=RaMailer.create_expired("railspki@rheoli.net", "user@rheoli.net", {"dn"=>ra["dn"]})
    #o.set_content_type("text/plain")
    #RaMailer.deliver(o)
  end

end
