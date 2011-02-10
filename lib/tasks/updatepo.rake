desc "Update pot/po files to match new version." 
task :updatepo do
  MY_APP_TEXT_DOMAIN = "railspki"
  MY_APP_VERSION     = "railspki 1.0" 
  GetText.update_pofiles(MY_APP_TEXT_DOMAIN, 
                         Dir.glob("{app/views,app/controllers,lib}/**/*.{rb,rhtml,haml}"), 
                         MY_APP_VERSION)
end
