require File.dirname(__FILE__) + '/../test_helper'

class RolePermissionTest < Test::Unit::TestCase
  fixtures :roles, :permissions

  def test_should_add_and_remove_association
    assert_nil roles(:poweruser).permissions.detect { |perm| perm.access_name == permissions(:golden_key).access_name }
    assert RolePermission.add(roles(:poweruser).id, permissions(:golden_key).id)
    assert_equal :no_role, RolePermission.add(31427, permissions(:golden_key).id)
    assert_equal :no_perm, RolePermission.add(roles(:poweruser).id, 31427)
    roles(:poweruser).reload
    assert_not_nil roles(:poweruser).permissions.detect { |perm| perm.access_name == permissions(:golden_key).access_name }
    assert RolePermission.remove(roles(:poweruser).id, permissions(:golden_key).id)
    assert_equal :no_association, RolePermission.remove(roles(:poweruser).id, permissions(:golden_key).id)
  end
end
