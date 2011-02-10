class UpdateResult < ActionWebService::Struct
  member :id,         :int
  member :updated_on, :time
end

class BackendApi < ActionWebService::API::Base
  api_method :find_all_requests, :returns => [[:int]]
  api_method :find_request_by_id, :expects => [:int], :returns => [RaItem]
  api_method :find_to_sign, :returns => [[RaItem]]
  api_method :update_ra_item, :expects => [CaItem], :returns => [:bool]
  api_method :find_update, :expects => [:string], :returns => [[UpdateResult]]
  api_method :update_entries, :expects => [:string,[:string]], :returns => [:bool]
  api_method :delete_entries, :expects => [:string,[:int]], :returns => [:bool]
  api_method :role_links, :expects => [:int,[:int],[:int]], :returns => [:bool]
end

