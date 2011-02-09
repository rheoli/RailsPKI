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

class UserRoleSchema < ActiveRecord::Migration
  def self.up
    create_table "users", :force => true do |t|
      t.column :username,           :string, :limit => 40
      t.column :email,              :string, :limit => 100
      t.column :email_cc,           :text
      t.column :password_salt,      :string
      t.column :password_hash,      :string
      t.column :created_on,         :datetime
      t.column :updated_on,         :datetime
    end
    
    create_table "roles_users", :force => true, :id => false do |t|
      t.column :role_id,            :integer
      t.column :user_id,            :integer
    end

    create_table "roles", :force => true do |t|
      t.column :name,               :string, :limit => 40
      t.column :ca_domain_id,       :integer
      t.column :ra_server_id,       :integer
      t.column :created_on,         :datetime
      t.column :updated_on,         :datetime
    end

    create_table "auth_methods_roles", :force => true, :id => false do |t|
      t.column :role_id,            :integer
      t.column :auth_method_id,     :integer
    end
    
    create_table "auth_methods", :force => true do |t|
      t.column :name,               :string, :limit => 20, :null => false
      t.column :meth,               :text
    end
    
  end

  def self.down
    drop_table :auth_methods
    drop_table :users
    drop_table :roles
    drop_table :auth_methods_roles
    drop_table :roles_users
  end
end

#=EOF
