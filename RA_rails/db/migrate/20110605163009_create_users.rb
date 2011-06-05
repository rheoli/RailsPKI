class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.text :name
      t.text :login
      t.text :password

      t.timestamps
    end
  end

  def self.down
    drop_table :users
  end
end
