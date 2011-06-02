class RaMailer < ActionMailer::Base

  def check(_sFrom, _aTo, _hInfo, sent_at = Time.now)
    @subject    = "RA Info"
    @body       = { "info" => _hInfo }
    @recipients = _aTo
    @from       = _sFrom
    @sent_on    = sent_at
    @headers    = {}
  end

  def expired(_sFrom, _aTo, _hInfo, sent_at = Time.now)
    @subject    = "RA Info"
    @body       = { "info" => _hInfo }
    @recipients = _aTo
    @from       = _sFrom
    @sent_on    = sent_at
    @headers    = {}
  end
end
