#-WithLdap init

require 'active_record/base_with_ldap'

ldap_configuration_file = File.join(RAILS_ROOT, 'config', 'ldap.yml')
if File.exists?(ldap_configuration_file)
  configurations = YAML::load(ERB.new(IO.read(ldap_configuration_file)).result)
  ActiveRecord::BaseWithLdap.configuration(configurations[ENV['RAILS_ENV']])
end

#=EOF
