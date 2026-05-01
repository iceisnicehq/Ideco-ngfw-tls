-- wrk: Connection: close — по возможности новые TCP/TLS соединения (полные рукопожатия).
request = function()
  local headers = {}
  headers["Connection"] = "close"
  return wrk.format("GET", "/", nil, headers)
end
