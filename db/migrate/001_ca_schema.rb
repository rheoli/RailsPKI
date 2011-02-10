#--
# Copyright (c) 2006 Stephan Toggweiler
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

class CaSchema < ActiveRecord::Migration
  def self.up    
    create_table "ca_domains", :force => true do |t|
      t.column :name,               :string, :limit => 200
      t.column :yaml,               :text
      t.column :bits,               :integer, :default => 1024, :null => false
      t.column :pubkey_pem,         :text
      t.column :privkey_pem,        :text
      t.column :dn,                 :text
      t.column :dn_policy,          :text
      t.column :extensions,         :text
      t.column :config,             :text
      t.column :ca_domain_id,       :integer, :default => 0, :null => false
      t.column :version,            :integer, :default => 1, :null => false
      t.column :created_on,         :datetime
      t.column :updated_on,         :datetime
    end

    create_table "ca_items", :force => true do |t|
      t.column :crt_serial,         :string, :limit => 100
      t.column :crt_begin,          :time
      t.column :crt_end,            :time
      t.column :csr,                :text
      t.column :crt_pem,            :text
      t.column :dn,                 :text
      t.column :state,              :string, :limit => 30, :default => 'none'
      t.column :user_id,            :integer, :default => 0, :null => false
      t.column :signer_user_id,     :integer, :default => 0, :null => false
      t.column :duration,           :integer, :default => 365
      t.column :purpose,            :text
      t.column :ca_domain_id,       :integer, :null => false
      t.column :ra_server_id,       :integer, :null => false
      t.column :ra_item_id,         :integer, :null => false
      t.column :supersede_item_id,  :integer
      t.column :created_on,         :datetime
      t.column :updated_on,         :datetime
    end

    create_table "ca_domains_ra_servers", :force => true, :id => false do |t|
      t.column :ca_domain_id,       :integer
      t.column :ra_server_id,       :integer
    end

    create_table "ra_servers", :force => true do |t|
      t.column :name,               :string, :limit => 200
      t.column :ca_item_id,         :integer, :null => false
      t.column :disabled,           :boolean, :default=>true
      t.column :created_on,         :datetime
      t.column :updated_on,         :datetime
    end
    RaServer.create :name=>"-local-", :ca_item_id=>0

    create_table "ca_revokes", :force => true do |t|
      t.column :ca_item_id,         :integer
      t.column :user_id,            :integer, :default => 0, :null => false
      t.column :reason,             :string, :limit => 30, :default => ''
      t.column :created_on,         :datetime
      t.column :updated_on,         :datetime
    end
  end

  def self.down
    drop_table :ca_domains
    drop_table :ca_items
    drop_table :ra_servers
    drop_table :ca_domains_ra_servers
    drop_table :ca_revokes
  end
end

#=EOF
