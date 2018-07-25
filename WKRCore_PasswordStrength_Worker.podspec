Pod::Spec.new do |s|

  s.name         = "WKRCore_PasswordStrength_Worker"
  s.version      = "0.2.0"
  s.summary      = "A Core Password Strength Worker."

  s.description  = <<-DESC
                    A basic core worker for calculating the strength of a password
                   DESC

  s.homepage     = "https://github.com/DoubleNode/Pod_WKRCore_PasswordStrength_Worker"
  s.license      = { :type => "PRIVATE", :file => "README.md" }

  s.author             = { "Darren Ehlers" => "me@darrenehlers.com" }
  s.social_media_url   = "http://twitter.com/ehlersd"

  s.platform     = :ios, "9.0"

  s.source = { :git => "https://github.com/DoubleNode/Pod_WKRCore_PasswordStrength_Worker.git", :tag => "#{s.version}" }

  s.source_files  = "Classes", "Classes/**/*.{h,m}"
  s.exclude_files = "Classes/Exclude"

  s.public_header_files = "Classes/**/*.h"

  s.requires_arc = true

  # s.xcconfig = { "HEADER_SEARCH_PATHS" => "$(SDKROOT)/usr/include/libxml2" }
  s.dependency "DNCProtocols"

end
