require './tmp/single_sign_on'
sso = SingleSignOn.new.tap { |s| s.email = 'user@email.com'; s.external_id = "123";
  s.sso_secret = 'b54cc7b3e42b215d1792c300487f1cb1'; s.nonce = '228cd25bd24bbc31a2bfc81ff8ea6d39' }
sso.to_url("https://mail.gather.coop")
