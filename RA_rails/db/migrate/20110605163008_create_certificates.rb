class CreateCertificates < ActiveRecord::Migration
  def self.up
    create_table :certificates do |t|
      t.text :name
      t.text :req
      t.text :crt

      t.timestamps
    end
  end

  def self.down
    drop_table :certificates
  end
end
