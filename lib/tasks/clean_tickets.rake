desc 'Remove tickets from database'

task :clean_tickets => :environment do
  ActiveRecord::Base.establish_connection
  ActiveRecord::Base.connection.delete("delete from blabka")
end
