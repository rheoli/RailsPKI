module AuthenticatedSystem

  def self.included(base)
    base.send( :helper_method, :current_user ) if base.respond_to? :helper_method
  end
  
  def current_user
    @current_user ||= session[:user] ? User.find(session[:user]) : nil
  end
  
  def current_user_set( new_user )
    session[:user] = new_user ? new_user.id : nil
    @current_user = new_user
  end
  
  def clear_return_location
    session[:return_location_hash] = nil
  end

  def store_return_location
    session[:return_location_hash] = { :action => action_name, :controller => controller_name }
    logger.info("store_return_location of #{session[:return_location_hash].inspect}")
  end
  
  def redirect_back_or_goto( default_location = home_url )
    redirect_location = session[:return_location_hash]
    session[:return_location_hash] = nil
    if redirect_location
      redirect_to redirect_location
    else
      redirect_to default_location
    end
  end

end