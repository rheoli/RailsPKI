require File.dirname(__FILE__) + '/../test_helper'

class UserTest < Test::Unit::TestCase
  fixtures :users, :roles, :user_roles, :permissions, :role_permissions

  def test_should_have_association_between_user_and_roles
    assert_equal 2, users(:billy).roles.length
    assert_not_nil users(:billy).roles.detect { |role| role.name == roles(:poweruser).name }
    assert_equal 1, users(:sara).roles.length
    assert_nil users(:sara).roles.detect { |role| role.name == roles(:poweruser).name }
  end
  
  def test_should_be_able_to_check_permissions
    assert users(:billy).permission?(:golden_key)
    assert users(:billy).permission?(:read_power)
    
    assert users(:sara).permission?(:golden_key)
    assert_equal false, users(:sara).permission?(:write_power)
  end
end
