require 'net/ldap'

module RailsPKI

class Find

  def self.find(_info, _uid)
    auth = {
      :method   => :simple,
      :username => _info["dn"],
      :password => _info["dn_pwd"],
    }
    conn=Net::LDAP.new :host=>_info["server"], :port=>389, :auth=>auth
    if conn.class!=Net::LDAP
      return(nil)
    end
    search={
      :filter=>Net::LDAP::Filter.eq("cn",_uid)&Net::LDAP::Filter.eq("objectclass","user"),
      :scope=>Net::LDAP::SearchScope_WholeSubtree,
      :base=>_info["base"],
      :attributes=>["cn","dn","mail","givenname","sn"]
    }
    res=conn.search search
    return(nil) if res.size!=1
    res=res[0]
    return(nil) if res[:dn].nil?
    res
  end

end
end
