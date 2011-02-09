class BackendApi < ActionWebService::API::Base
  api_method :find_all_requests,
             :returns => [[:int]]
  api_method :find_request_by_id,
             :expects => [:int],
             :returns => [RaItem]
end
