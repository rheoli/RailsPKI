class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.text :user
      t.text :description
      t.text :password
      t.timestamps
    end
  end
end
