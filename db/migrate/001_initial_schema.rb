class InitialSchema < ActiveRecord::Migration
  def self.up
    create_table "ca_definitions", :force => true do |t|
      t.column "name", :string, :limit => 200
      t.column "yaml", :string, :limit => 300
      t.column "bits", :integer, :default => 1024, :null => false
      t.column "pubkey_pem", :text
      t.column "privkey_pem", :text
      t.column "dn", :text
      t.column "dn_policy", :text
      t.column "extensions", :text
      t.column "config", :text
      t.column "ca_definition_id", :integer, :default => 0, :null => false
      t.column "version", :integer, :default => 1, :null => false
    end

    create_table "ra_items", :force => true do |t|
      t.column "crt_serial", :string, :limit => 100
      t.column "crt_begin", :time
      t.column "crt_end", :time
      t.column "csr", :text
      t.column "crt_pem", :text
      t.column "dn", :text
      t.column "state", :string, :limit => 30, :default => 'none'
      t.column "user_id", :integer, :default => 0, :null => false
      t.column "ca_definition_id", :integer, :null => false
      t.column "created_on", :datetime
      t.column "updated_on", :datetime
    end

    create_table "ca_items", :force => true do |t|
      t.column "crt_serial", :string, :limit => 100
      t.column "crt_begin", :time
      t.column "crt_end", :time
      t.column "csr", :text
      t.column "crt_pem", :text
      t.column "dn", :text
      t.column "state", :string, :limit => 30, :default => 'none'
      t.column "user_id", :integer, :default => 0, :null => false
      t.column "ca_definition_id", :integer, :null => false
      t.column "ra_server_id", :integer, :null => false
      t.column "ra_item_id", :integer, :null => false
      t.column "created_on", :datetime
      t.column "updated_on", :datetime
    end

    create_table "ra_roles", :force => true do |t|
      t.column "name", :string, :limit => 100
      t.column "dn", :text
      t.column "ca_definition_id", :integer, :default => 0, :null => false
    end

    create_table "ra_reqgens", :force => true do |t|
      t.column "cn", :string, :limit => 100, :null => false
      t.column "o", :string, :limit => 100, :null => false
      t.column "ou", :string, :limit => 100
      t.column "l", :string, :limit => 100, :null => false
      t.column "st", :string, :limit => 100, :null => false
      t.column "c", :string, :limit => 2, :null => false
      t.column "bits", :string, :limit => 20, :null => false
      t.column "password", :string, :limit => 30, :null => false
    end

    create_table "ra_servers", :force => true do |t|
      t.column "name", :string, :limit => 200
      t.column "client_crt", :text
      t.column "client_key", :text
    end
    RaServer.create :name=>"-local-", :client_crt=>"", :client_key=>""

    create_table "ra_user_roles", :force => true do |t|
      t.column "ra_user_id", :integer, :default => 0, :null => false
      t.column "ra_role_id", :integer, :default => 0, :null => false
    end

    create_table "ra_user_auth_methods", :force => true do |t|
      t.column "name", :string, :limit => 20, :null => false
      t.column "auth_descr", :text
    end

    create_table "ra_users", :force => true do |t|
      t.column "name", :string, :limit => 20, :null => false
      t.column "ra_user_auth_method_id", :integer, :default => 0, :null => false
    end
    
    create_table "ca_users", :force => true do |t|
      t.column "name", :string, :limit => 40, :null => false
      t.column "dn", :string, :limit => 200, :null => false
    end
    
  end

  def self.down
    drop_table :ca_definitions
    drop_table :ra_items
    drop_table :ra_reqgens
    drop_table :ra_servers
    drop_table :ra_roles
    drop_table :ra_user_roles
    drop_table :ra_user_auth_methods
    drop_table :ra_users
    drop_table :ca_users
  end
end

#=EOF
