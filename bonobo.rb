require 'openssl'
require 'base64'
require 'fgraph'
require 'json'
require 'dalli'
require 'erb'

require 'sinatra/base'

require 'config'

class Bonobo < Sinatra::Base
  set :cache, Dalli::Client.new
  set :public, File.dirname(__FILE__) + '/public'
  
  before do
    @key = OpenSSL::PKey::RSA.new(File.read(File.dirname(__FILE__) + '/privatekey.pem'))
  end

  get '/' do
    erb :index
  end

  get '/includes' do
    id = params[:id]
    nonce = params[:nonce]
    collection = params[:collection]
    return "Invalid" unless id and nonce and collection
  
    fb_hash = hash_from_cookie("fbs_#{FACEBOOK_APP_ID}")
    client = FGraph::Client.new(:access_token => fb_hash["access_token"])
    friend = nil
    if (collection == "friends" and fb_hash["uid"] == id)
      friend = true
    else
      friends = settings.cache.fetch("#{collection}.#{fb_hash["uid"]}", 60) { client.me(collection) }
      friend = friends.find {|elm| elm["id"] == id}
    end
    if friend
      JSON.dump({:result => true, :signature =>
        Base64.encode64(@key.sign(OpenSSL::Digest::SHA1.new, "#{collection}|#{id}|#{nonce}"))})
    else
      JSON.dump({:result => false, :signature =>
        Base64.encode64(@key.sign(OpenSSL::Digest::SHA1.new, "!#{collection}|#{id}|#{nonce}"))})
    end
  end

#  get '/publickey.pem' do
#    cert = OpenSSL::X509::Certificate.new
#    cert.public_key = @key.public_key
#    return cert.to_pem
#  end

  protected
  def hash_from_cookie(name)
    cookie = JSON.parse("[#{request.cookies[name]}]").first
    result = cookie.split("&").map {|c| c.split("=") }.inject({}) {|result, elm| result[elm.first] = elm.last; result}
    return result
  end
  
  run! if app_file == $0
end