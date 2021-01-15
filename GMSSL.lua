-- @brief GMSSL Protocol dissector plugin
-- @author ccs
-- @date 20210113

-- create a new dissector
local NAME = "GMSSL"
local PORT = 443
local GMSSL = Proto(NAME, "GMSSL Protocol")

local fields = GMSSL.fields
fields.ContentType = ProtoField.uint8 (NAME .. ".ContentType", "ContentType")
fields.MajorVersion = ProtoField.uint8 (NAME .. ".MajorVersion", "MajorVersion")
fields.MinorVersion = ProtoField.uint8 (NAME .. ".MinorVersion", "MinorVersion")
fields.length = ProtoField.uint16(NAME .. ".length", "Length")

fields.helloType = ProtoField.uint8(NAME .. ".Hello.Type", "Hello")
fields.helloLength = ProtoField.uint24(NAME .. ".Hello.Length", "Length")
fields.helloMajorVersion = ProtoField.uint8(NAME .. ".Hello.MajorVersion", "MajorVersion")
fields.helloMinorVersion = ProtoField.uint8(NAME .. ".Hello.MinorVersion", "MinorVersion")
fields.helloTime = ProtoField.uint32(NAME .. ".Hello.Time", "Time")
fields.helloRand = ProtoField.bytes(NAME .. ".Hello.Random", "Random")
fields.helloSesIdLen = ProtoField.uint8(NAME .. ".Hello.SesIdLen", "SessionIdLen")
fields.helloSesId = ProtoField.bytes(NAME .. ".Hello.SesId", "SessionId")

fields.helloCipherSuiteLen = ProtoField.uint16(NAME .. ".Hello.CipherSuiteLen", "CipherSuiteLen")
fields.helloCipherSuite = ProtoField.string(NAME .. ".Hello.CipherSuite", "CipherSuite")
fields.helloCipherSuiteValue = ProtoField.uint16(NAME .. ".Hello.CipherSuite.CipherSuiteValue", "CipherSuite")

fields.helloCompessMethodLen = ProtoField.uint8(NAME .. ".Hello.CompressMethodLen", "COmpressMethodLen")
fields.helloCompessMethod = ProtoField.bytes(NAME .. ".Hello.CompressMethod", "CompressMethod")

fields.helloExtensionLen = ProtoField.uint16(NAME .. ".Hello.ExtensionLen", "ExtensionLen")
fields.helloExtension = ProtoField.bytes(NAME .. ".Hello.Extension", "Extension")

fields.helloCertLen = ProtoField.uint24(NAME .. ".Hello.CertLen", "CertLen")
fields.helloCert = ProtoField.bytes(NAME .. ".Hello.CertLen", "CertLen")

fields.keyExchangeLen = ProtoField.uint24(NAME .. ".Hello.KeyExchangeLen", "KeyExchangeLen")
fields.keyExchange = ProtoField.bytes(NAME .. ".Hello.KeyExchange", "KeyExchange")

fields.helloDoneLeng = ProtoField.uint24(NAME .. ".Hello.ServerHelloDoneLen", "Length")

fields.certReqLen = ProtoField.uint24(NAME .. ".Hello.CertReqLen", "Length")
fields.certReq = ProtoField.bytes(NAME .. ".Hello.CertReq", "CertReq")

fields.clientKeyExchange = ProtoField.uint8(NAME .. ".Hello.ClientKeyExchange", "ClientKeyExchange")
fields.clientKeyExchangeLen = ProtoField.uint24(NAME .. ".Hello.ClientKeyExchange", "ClientKeyExchangeLen")
fields.clientKeyExchangeData = ProtoField.bytes(NAME .. ".Hello.ClientKeyExchangeData", "ClientKeyExchangeData")

fields.certVerify = ProtoField.uint8(NAME .. ".Hello.CertVerify", "CertVerify")
fields.certVerifyLen = ProtoField.uint24(NAME .. ".Hello.CertVerifyLen", "CertVerifyLen")
fields.certVerifyData = ProtoField.bytes(NAME .. ".Hello.CertVerifyData", "CertVerifyData")

fields.changeCipherSpecMessage = ProtoField.uint8(NAME .. ".Hello.ChangeCipherSpecMessage", "ChangeCipherSpecMessage")

fields.applicationDataLen = ProtoField.uint24(NAME .. ".Hello.ApplicationDataLen", "ApplicationDataLen")
fields.applicationData = ProtoField.bytes(NAME .. ".Hello.ApplicationData", "ApplicationData")

fields.encryptedHelloData = ProtoField.bytes(NAME .. ".EncryptedHelloData", "EncryptedHelloData")

fields.alertData = ProtoField.bytes(NAME .. ".AlertData", "AlertData")

--local clientHello = GMSSL.fields.clientHello

-- dissect packet
function GMSSL.dissector (tvb, pinfo, tree)
	local offset = 0
	local isgm = 0
	isgm = tvb(1, 2)
	-- GMSSL version is 1.1
	if (isgm:uint() ~= 0x0101)
	then
		Dissector.get("tls"):call(tvb, pinfo, tree) -- Decode as origial TLS
		return
	end

	local changeCipherOk = false
	-- If GM ssl.
	local maintree = tree:add(GMSSL, tvb())
	pinfo.cols.protocol = GMSSL.name
	local parseoff = 0
	local infoMsg = ""
	while (offset < tvb:len())
	do
		local type = tvb(offset, 1)
		local subtree = maintree:add(GMSSL, tvb())

		subtree:add(fields.ContentType, type)
		local contentType = "Hello"
		local dataType = type:uint()
		
		offset = offset + 1	
		type = tvb(offset, 1)
		subtree:add(fields.MajorVersion, type)
		local majorVersion = type

		offset = offset + 1	
		type = tvb(offset, 1)
		local minorVersion = type
		local verStr = 
		subtree:add(fields.MinorVersion, type):append_text(string.format(": Version: %d.%d", majorVersion:uint(), minorVersion:uint()))
	
	
		offset = offset + 1
		type = tvb(offset, 2)
		subtree:add(fields.length, type):append_text(": DataLength")
		subtree:append_text(", Length: " .. type:uint())

		offset = offset + 2

		if(dataType == 22)
		then
			contentType = "HandShake Protocol"
		elseif(dataType == 20)
		then
			contentType = "Change Cipher Spec Protocol"
		elseif (dataType == 21)
		then
			contentType = "Alert"
		elseif (dataType == 23)
		then
			contentType = "ApplicationData"
			subtree:add(fields.applicationData, tvb(offset, type:uint()))
			offset = offset + type:uint()
			infoMsg = infoMsg .. "Application Data;"
		elseif (dataType == 80)
		then
			contentType = "Site2Site"
		else
			contentType = "Unknown"
		end
		subtree:append_text(": " .. contentType)

		if(dataType == 20)
		then -- ChangeCipherSpec  one bytes.
			subtree:append_text(": Change Cipher Spec")
			infoMsg = infoMsg .. "Change Cipher Spec;"
			subtree:add(fields.changeCipherSpecMessage, tvb(offset, type:uint()))
			offset = offset + type:uint()
			changeCipherOk = true
		elseif(dataType == 21) -- Alert
		then
			subtree:append_text(": Alert")
			infoMsg = infoMsg .. "Alert;"
			subtree:add(fields.alertData, tvb(offset, type:uint()))
			offset = offset + type:uint()
		elseif(dataType == 22) -- handshake process
		then
			-- After ChangeCipherSuite,It's Maybe A Hello EncryptedData, It's Also Handshake Message
			-- It's May be EncrypteData. If ChangeCipherSpec Completed
			if(changeCipherOk)
			then
				subtree:append_text(": Encrypted HandShake Message")
				infoMsg = infoMsg .. "Encrypted HandShake Message;"
				subtree:add(fields.encryptedHelloData, tvb(offset, type:uint()))
				offset = offset + type:uint()
				changeCipherOk = false
			else
				-- parse types.		
				type = tvb(offset, 1)
				if (type:uint() == 1)
				then
					subtree:append_text(": Client Hello")
					infoMsg = infoMsg .. "Client Hello;"
					parseoff = parseClientHello(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 2)
				then
					subtree:append_text(": Server Hello")
					infoMsg = infoMsg .. "Server Hello;"
					parseoff = parseServerHello(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 11)
				then
					--	certificate
					subtree:append_text(": Certficate")
					infoMsg = infoMsg .. "Certficate;"
					parseoff = parseCertficate(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 12)
				then
					-- server key exchange
					subtree:append_text(": Server Key Exchange")
					infoMsg = infoMsg .. "Server Key Exchange;"
					parseoff = parseServerKeyExchange(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 13)
				then
					--	certificate request
					subtree:append_text(": Certificate Request")
					infoMsg = infoMsg .. "Certificate Request;"
					parseoff = parseCertficateRequest(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 14)
				then
					--	server hello done
					subtree:append_text(": Server Hello Done")
					infoMsg = infoMsg .. "Server Hello Done;"
					parseoff = parseServerHelloDone(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 15)
				then
					--	certificate verify
					subtree:append_text(": Certificate Verify")
					infoMsg = infoMsg .. "Certificate Verify;"
					parseoff = parseCertificateverify(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 16)
				then
					--	client key exchange
					subtree:append_text(": Client Key Exchange")
					infoMsg = infoMsg .. "Client Key Exchange;"
					parseoff = parseClientKeyExchange(tvb(offset):tvb(), pinfo, subtree)
					offset = offset + parseoff
				elseif (type:uint() == 20)
				then
					--	finished
					subtree:append_text(": Finished")
					infoMsg = infoMsg .. "Finished;"
				end
			end
		end
	end

	pinfo.cols.info = infoMsg
end

function parseClientHello(tvb, pinfo, tree) 
	local subtree = tree:add_le("ClientHello")
	--subtree:append_text("subtree:ClientHello")
	local offset = 0
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ClientHello")
	offset = offset + 1
	local length = tvb(offset, 3)
	subtree:add(fields.helloLength, length):append_text(": HelloLength")
	offset = offset + 3

	local majorVersion = tvb(offset, 1)
	offset = offset + 1
	local minorVersion = tvb(offset, 1)
	offset = offset + 1
	subtree:add(fields.helloMajorVersion, majorVersion)
	subtree:add(fields.helloMinorVersion, minorVersion):append_text(": 协议版本:" .. string.format("%d.%d", majorVersion:uint(), minorVersion:uint()))
	-- 随机数
	local times = tvb(offset, 4)
	offset = offset + 4
	subtree:add(fields.helloTime, times):append_text(": " .. os.date("%Y-%m-%d %H:%M:%S",times:uint()))

	subtree:add(fields.helloRand, tvb(offset, 28))
	offset = offset + 28

	-- 检测是否有SessionID
	local sessionIdLen = tvb(offset, 1):uint()
	offset = offset + 1
	subtree:add(fields.helloSesIdLen, sessionIdLen)
	if (sessionIdLen > 0)
	then
		subtree:add(fields.helloSesId, tvb(offset, sessionIdLen))
		offset = offset + sessionIdLen
	end
	local cipherSuiteLen = tvb(offset, 2):uint()
	subtree:add(fields.helloCipherSuiteLen, cipherSuiteLen)
	offset = offset + 2
	if (cipherSuiteLen >= 2)
	then
		stree = subtree:add(fields.helloCipherSuite,string.format("(%d) Suites", cipherSuiteLen / 2))
		for indx = 1, cipherSuiteLen / 2, 1 do
			stree:add(fields.helloCipherSuiteValue, tvb(offset, 2)):append_text(string.format(": 0x%04X:%s", tvb(offset, 2):uint(), getCipherSuite(tvb(offset, 2):uint())))
			offset = offset + 2
		end
	end
	-- compress
	subtree:add(fields.helloCompessMethodLen, tvb(offset, 1))	
	local compressMethodLen = tvb(offset, 1):uint()
	offset = offset + 1
	if (compressMethodLen > 0)
	then
		subtree:add(fields.helloCompessMethod, tvb(offset, compressMethodLen))
		offset = offset + compressMethodLen
	end
	
	local parseExtenOffset = parseExtensions(tvb(offset):tvb(), pinfo, subtree)
	offset = offset + parseExtenOffset
	return offset
end

-- parse Server Hello
function parseServerHello(tvb, pinfo, tree)
	local subtree = tree:add_le("ServerHello")
	--subtree:append_text("subtree:ClientHello")
	local offset = 0
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ServerHello")
	offset = offset + 1
	local length = tvb(offset, 3)
	subtree:add(fields.helloLength, length):append_text(": ServerHelloLength")
	offset = offset + 3

	local majorVersion = tvb(offset, 1)
	offset = offset + 1
	local minorVersion = tvb(offset, 1)
	offset = offset + 1
	subtree:add(fields.helloMajorVersion, majorVersion)
	subtree:add(fields.helloMinorVersion, minorVersion):append_text(": 协议版本:" .. string.format("%d.%d", majorVersion:uint(), minorVersion:uint()))
	-- 随机数
	local times = tvb(offset, 4)
	offset = offset + 4
	subtree:add(fields.helloTime, times):append_text(": " .. os.date("%Y-%m-%d %H:%M:%S",times:uint()))

	subtree:add(fields.helloRand, tvb(offset, 28))
	offset = offset + 28

	-- 检测是否有SessionID
	local sessionIdLen = tvb(offset, 1):uint()
	offset = offset + 1
	subtree:add(fields.helloSesIdLen, sessionIdLen)
	if (sessionIdLen > 0)
	then
		subtree:add(fields.helloSesId, tvb(offset, sessionIdLen))
		offset = offset + sessionIdLen
	end
	local cipherSuite = tvb(offset, 2):uint()
	subtree:add(fields.helloCipherSuite, cipherSuite):append_text(string.format(": 0x%04X:%s", cipherSuite, getCipherSuite(cipherSuite)))
	offset = offset + 2
	
	-- compress
	subtree:add(fields.helloCompessMethodLen, tvb(offset, 1))	
	local compressMethodLen = tvb(offset, 1):uint()
	offset = offset + 1
	if (compressMethodLen > 0)
	then
		subtree:add(fields.helloCompessMethod, tvb(offset, compressMethodLen))
		offset = offset + compressMethodLen
	end

	-- Next Maybe Not Extensions.
	local parseExtenOffset = parseExtensions(tvb(offset):tvb(), pinfo, subtree)
	offset = offset + parseExtenOffset
	return offset
end


function parseCertficate(tvb, pinfo, tree)
	local offset = 0

	local subtree = tree:add_le("Certificate")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": Certficate")
	offset = offset + 1
	-- Total Length
	local totalLen = tvb(offset, 3):uint()	
	subtree:add(fields.helloCertLen, tvb(offset, 3)):append_text(": DataLength")
	offset = offset + 3

	local cert0Len = tvb(offset, 3):uint()
	subtree:add(fields.helloCertLen, tvb(offset, 3)):append_text(": CertLength")
	offset = offset + 3

	local paseLens = 0
	while(paseLens < cert0Len)
	do
		-- parse one certs.
		stree = subtree:add(fields.helloCert,string.format("One Certs"))
		stree:add(fields.helloCertLen, tvb(offset, 3))
		local onecertLen = tvb(offset, 3):uint()
		offset = offset + 3
		stree:add(fields.helloCert, tvb(offset, onecertLen))
		offset = offset + onecertLen

		paseLens = paseLens + 3 + onecertLen
	end
	return offset
end

function parseServerKeyExchange(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("ServerKeyExchange")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ServerKeyExchange")
	offset = offset + 1

	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.keyExchangeLen, tvb(offset, 3)):append_text(": Length")
	offset = offset + 3

	subtree:add(fields.keyExchange, tvb(offset, lengs)):append_text(": Length")
	offset = offset + lengs
	return offset
end

function parseServerHelloDone(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("ServerHelloDone")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": ServerHelloDone")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.helloDoneLeng, tvb(offset, 3)):append_text(": Length")
	offset = offset + 3
	return offset
end

function parseCertficateRequest(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("CertficateRequest")
	local type = tvb(offset, 1)
	subtree:add(fields.helloType, type):append_text(": CertficateRequest")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.certReqLen, tvb(offset, 3)):append_text(": Length")
	offset = offset + 3
	subtree:add(fields.certReq, tvb(offset, lengs)):append_text(": CertReq")
	offset = offset + lengs
	return offset
end

function parseClientKeyExchange(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("ClientKeyExchange")
	local type = tvb(offset, 1)
	subtree:add(fields.clientKeyExchange, type):append_text(": ClientKeyExchange")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.clientKeyExchangeLen, tvb(offset, 3)):append_text(": ClientKeyExchangeLen")
	offset = offset + 3

	subtree:add(fields.clientKeyExchangeData, tvb(offset, lengs)):append_text(": clientKeyExchangeData")
	offset = offset + lengs
	return offset
end

function parseCertificateverify(tvb, pinfo, tree)
	local offset = 0
	local subtree = tree:add_le("CertVerify")
	local type = tvb(offset, 1)
	subtree:add(fields.certVerify, type):append_text(": CertVerify")
	offset = offset + 1
	local lengs = tvb(offset, 3):uint()
	subtree:add(fields.certVerifyLen, tvb(offset, 3)):append_text(": CertVerifyLen")
	offset = offset + 3

	subtree:add(fields.certVerifyData, tvb(offset, lengs)):append_text(": CertVerifyData")
	offset = offset + lengs
	return offset
end

-- Parse Extensions, Maybe Have No extensions.
-- Before parse, We must detect the head.
function parseExtensions(tvb, pinfo, tree)
	if (tvb:len() < 1)
	then
		return 0
	end
	if (tvb:len() > 4)
	then
		local content = tvb(0, 1):uint() -- Try to parse it as content.
		local ver = tvb(1, 2):uint() -- Try to parse it as Version.
		--Next Content is Not Extensions. Also Handshake Protocol
		if (content == 0x16 and ver == 0x0101)
		then
			return 0 -- No Extensions and other type parsed.
		end
	end
	-- Now, The buf is extensions.
	local offset = 0
	local extensionLen = tvb(offset, 2):uint()	
	tree:add(fields.helloExtensionLen, tvb(offset, 2))
	offset = offset + 2
	if (extensionLen > 0)
	then
		tree:add(fields.helloExtension, tvb(offset, extensionLen))
		offset = offset + extensionLen
	end
	return offset
end

-- Get cipher suite by Cipher ID.
function getCipherSuite(cuiteId)
	local cuiteTable = {}
	cuiteTable[0x0001] = "TLS_RSA_WITH_NULL_MD5"
    cuiteTable[0x0002] = "TLS_RSA_WITH_NULL_SHA"
    cuiteTable[0x0003] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
    cuiteTable[0x0004] = "TLS_RSA_WITH_RC4_128_MD5"
    cuiteTable[0x0005] = "TLS_RSA_WITH_RC4_128_SHA"
    cuiteTable[0x0006] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"
    cuiteTable[0x0007] = "TLS_RSA_WITH_IDEA_CBC_SHA"
    cuiteTable[0x0008] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x0009] = "TLS_RSA_WITH_DES_CBC_SHA"
    cuiteTable[0x000a] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x000b] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x000c] = "TLS_DH_DSS_WITH_DES_CBC_SHA"
    cuiteTable[0x000d] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x000e] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x000f] = "TLS_DH_RSA_WITH_DES_CBC_SHA"
    cuiteTable[0x0010] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0011] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x0012] = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
    cuiteTable[0x0013] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0014] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x0015] = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
    cuiteTable[0x0016] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0017] = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"
    cuiteTable[0x0018] = "TLS_DH_anon_WITH_RC4_128_MD5"
    cuiteTable[0x0019] = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"
    cuiteTable[0x001a] = "TLS_DH_anon_WITH_DES_CBC_SHA"
    cuiteTable[0x001b] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x001c] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA"
    cuiteTable[0x001d] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"
    cuiteTable[0x001e] = "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"
    cuiteTable[0x001E] = "TLS_KRB5_WITH_DES_CBC_SHA"
    cuiteTable[0x001F] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0020] = "TLS_KRB5_WITH_RC4_128_SHA"
    cuiteTable[0x0021] = "TLS_KRB5_WITH_IDEA_CBC_SHA"
    cuiteTable[0x0022] = "TLS_KRB5_WITH_DES_CBC_MD5"
    cuiteTable[0x0023] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"
    cuiteTable[0x0024] = "TLS_KRB5_WITH_RC4_128_MD5"
    cuiteTable[0x0025] = "TLS_KRB5_WITH_IDEA_CBC_MD5"
    cuiteTable[0x0026] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"
    cuiteTable[0x0027] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"
    cuiteTable[0x0028] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"
    cuiteTable[0x0029] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
    cuiteTable[0x002A] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"
    cuiteTable[0x002B] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
    cuiteTable[0x002C] = "TLS_PSK_WITH_NULL_SHA"
    cuiteTable[0x002D] = "TLS_DHE_PSK_WITH_NULL_SHA"
    cuiteTable[0x002E] = "TLS_RSA_PSK_WITH_NULL_SHA"
    cuiteTable[0x002F] = "TLS_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0030] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0031] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0032] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0033] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0034] = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0035] = "TLS_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0036] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0037] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0038] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0039] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0x003A] = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
    cuiteTable[0x003B] = "TLS_RSA_WITH_NULL_SHA256"
    cuiteTable[0x003C] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x003D] = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x003E] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x003F] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x0040] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x0041] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0042] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0043] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0044] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0045] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0046] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"
    cuiteTable[0x0060] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"
    cuiteTable[0x0061] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"
    cuiteTable[0x0062] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"
    cuiteTable[0x0063] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"
    cuiteTable[0x0064] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"
    cuiteTable[0x0065] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"
    cuiteTable[0x0066] = "TLS_DHE_DSS_WITH_RC4_128_SHA"
    cuiteTable[0x0067] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x0068] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x0069] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x006A] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x006B] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x006C] = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x006D] = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
    cuiteTable[0x0080] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT"
    cuiteTable[0x0081] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT"
    cuiteTable[0x0082] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411"
    cuiteTable[0x0083] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411"
    cuiteTable[0x0084] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0085] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0086] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0087] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0088] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x0089] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"
    cuiteTable[0x008A] = "TLS_PSK_WITH_RC4_128_SHA"
    cuiteTable[0x008B] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x008C] = "TLS_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0x008D] = "TLS_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0x008E] = "TLS_DHE_PSK_WITH_RC4_128_SHA"
    cuiteTable[0x008F] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0090] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0091] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0092] = "TLS_RSA_PSK_WITH_RC4_128_SHA"
    cuiteTable[0x0093] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0x0094] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0x0095] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0x0096] = "TLS_RSA_WITH_SEED_CBC_SHA"
    cuiteTable[0x0097] = "TLS_DH_DSS_WITH_SEED_CBC_SHA"
    cuiteTable[0x0098] = "TLS_DH_RSA_WITH_SEED_CBC_SHA"
    cuiteTable[0x0099] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
    cuiteTable[0x009A] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
    cuiteTable[0x009B] = "TLS_DH_anon_WITH_SEED_CBC_SHA"
    cuiteTable[0x009C] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x009D] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x009E] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x009F] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A0] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A1] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A2] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A3] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A4] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A5] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A6] = "TLS_DH_anon_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A7] = "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00A8] = "TLS_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00A9] = "TLS_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00AA] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00AB] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00AC] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0x00AD] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0x00AE] = "TLS_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x00AF] = "TLS_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0x00B0] = "TLS_PSK_WITH_NULL_SHA256"
    cuiteTable[0x00B1] = "TLS_PSK_WITH_NULL_SHA384"
    cuiteTable[0x00B2] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x00B3] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0x00B4] = "TLS_DHE_PSK_WITH_NULL_SHA256"
    cuiteTable[0x00B5] = "TLS_DHE_PSK_WITH_NULL_SHA384"
    cuiteTable[0x00B6] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0x00B7] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0x00B8] = "TLS_RSA_PSK_WITH_NULL_SHA256"
    cuiteTable[0x00B9] = "TLS_RSA_PSK_WITH_NULL_SHA384"
    cuiteTable[0x00BA] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BB] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BC] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BD] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BE] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00BF] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0x00C0] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C1] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C2] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C3] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C4] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C5] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"
    cuiteTable[0x00C6] = "TLS_SM4_GCM_SM3"
    cuiteTable[0x00C7] = "TLS_SM4_CCM_SM3"
    cuiteTable[0x00FF] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
    cuiteTable[0x0A0A] = "Reserved (GREASE)"
    cuiteTable[0x1301] = "TLS_AES_128_GCM_SHA256"
    cuiteTable[0x1302] = "TLS_AES_256_GCM_SHA384"
    cuiteTable[0x1303] = "TLS_CHACHA20_POLY1305_SHA256"
    cuiteTable[0x1304] = "TLS_AES_128_CCM_SHA256"
    cuiteTable[0x1305] = "TLS_AES_128_CCM_8_SHA256"
    cuiteTable[0x1A1A] = "Reserved (GREASE)"
    cuiteTable[0x2A2A] = "Reserved (GREASE)"
    cuiteTable[0x3A3A] = "Reserved (GREASE)"
    cuiteTable[0x4A4A] = "Reserved (GREASE)"
    cuiteTable[0x5600] = "TLS_FALLBACK_SCSV"
    cuiteTable[0x5A5A] = "Reserved (GREASE)"
    cuiteTable[0x6A6A] = "Reserved (GREASE)"
    cuiteTable[0x7A7A] = "Reserved (GREASE)"
    cuiteTable[0x8A8A] = "Reserved (GREASE)"
    cuiteTable[0x9A9A] = "Reserved (GREASE)"
    cuiteTable[0xAAAA] = "Reserved (GREASE)"
    cuiteTable[0xBABA] = "Reserved (GREASE)"
    cuiteTable[0xc001] = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
    cuiteTable[0xc002] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
    cuiteTable[0xc003] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc004] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc005] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc006] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
    cuiteTable[0xc007] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
    cuiteTable[0xc008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc00a] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc00b] = "TLS_ECDH_RSA_WITH_NULL_SHA"
    cuiteTable[0xc00c] = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
    cuiteTable[0xc00d] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc00e] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc00f] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc010] = "TLS_ECDHE_RSA_WITH_NULL_SHA"
    cuiteTable[0xc011] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
    cuiteTable[0xc012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xc015] = "TLS_ECDH_anon_WITH_NULL_SHA"
    cuiteTable[0xc016] = "TLS_ECDH_anon_WITH_RC4_128_SHA"
    cuiteTable[0xc017] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xc018] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"
    cuiteTable[0xc019] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC01A] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC01B] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC01C] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC01D] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC01E] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC01F] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC020] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC021] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC022] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC025] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC026] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC029] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC02A] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC02D] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC02E] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC031] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC032] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC033] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
    cuiteTable[0xC034] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xC035] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
    cuiteTable[0xC036] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
    cuiteTable[0xC037] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
    cuiteTable[0xC038] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
    cuiteTable[0xC039] = "TLS_ECDHE_PSK_WITH_NULL_SHA"
    cuiteTable[0xC03A] = "TLS_ECDHE_PSK_WITH_NULL_SHA256"
    cuiteTable[0xC03B] = "TLS_ECDHE_PSK_WITH_NULL_SHA384"
    cuiteTable[0xC03C] = "TLS_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC03D] = "TLS_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC03E] = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC03F] = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC040] = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC041] = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC042] = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC043] = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC044] = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC045] = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC046] = "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC047] = "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC048] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC049] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC04A] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC04B] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC04C] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC04D] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC04E] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC04F] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC050] = "TLS_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC051] = "TLS_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC052] = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC053] = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC054] = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC055] = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC056] = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC057] = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC058] = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC059] = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC05A] = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC05B] = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC05C] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC05D] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC05E] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC05F] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC060] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC061] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC062] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC063] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC064] = "TLS_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC065] = "TLS_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC066] = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC067] = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC068] = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC069] = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC06A] = "TLS_PSK_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC06B] = "TLS_PSK_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC06C] = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC06D] = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC06E] = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"
    cuiteTable[0xC06F] = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"
    cuiteTable[0xC070] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"
    cuiteTable[0xC071] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"
    cuiteTable[0xC072] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC073] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC074] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC075] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC076] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC077] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC078] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC079] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC07A] = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC07B] = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC07C] = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC07D] = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC07E] = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC07F] = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC080] = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC081] = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC082] = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC083] = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC084] = "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC085] = "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC086] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC087] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC088] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC089] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC08A] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC08B] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC08C] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC08D] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC08E] = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC08F] = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC090] = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC091] = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC092] = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"
    cuiteTable[0xC093] = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"
    cuiteTable[0xC094] = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC095] = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC096] = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC097] = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC098] = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC099] = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC09A] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
    cuiteTable[0xC09B] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
    cuiteTable[0xC09C] = "TLS_RSA_WITH_AES_128_CCM"
    cuiteTable[0xC09D] = "TLS_RSA_WITH_AES_256_CCM"
    cuiteTable[0xC09E] = "TLS_DHE_RSA_WITH_AES_128_CCM"
    cuiteTable[0xC09F] = "TLS_DHE_RSA_WITH_AES_256_CCM"
    cuiteTable[0xC0A0] = "TLS_RSA_WITH_AES_128_CCM_8"
    cuiteTable[0xC0A1] = "TLS_RSA_WITH_AES_256_CCM_8"
    cuiteTable[0xC0A2] = "TLS_DHE_RSA_WITH_AES_128_CCM_8"
    cuiteTable[0xC0A3] = "TLS_DHE_RSA_WITH_AES_256_CCM_8"
    cuiteTable[0xC0A4] = "TLS_PSK_WITH_AES_128_CCM"
    cuiteTable[0xC0A5] = "TLS_PSK_WITH_AES_256_CCM"
    cuiteTable[0xC0A6] = "TLS_DHE_PSK_WITH_AES_128_CCM"
    cuiteTable[0xC0A7] = "TLS_DHE_PSK_WITH_AES_256_CCM"
    cuiteTable[0xC0A8] = "TLS_PSK_WITH_AES_128_CCM_8"
    cuiteTable[0xC0A9] = "TLS_PSK_WITH_AES_256_CCM_8"
    cuiteTable[0xC0AA] = "TLS_PSK_DHE_WITH_AES_128_CCM_8"
    cuiteTable[0xC0AB] = "TLS_PSK_DHE_WITH_AES_256_CCM_8"
    cuiteTable[0xC0AC] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
    cuiteTable[0xC0AD] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
    cuiteTable[0xC0AE] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
    cuiteTable[0xC0AF] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
    cuiteTable[0xC0B0] = "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xC0B1] = "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xC0B2] = "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"
    cuiteTable[0xC0B3] = "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"
    cuiteTable[0xC0B4] = "TLS_SHA256_SHA256"
    cuiteTable[0xC0B5] = "TLS_SHA384_SHA384"
    cuiteTable[0xC0FF] = "TLS_ECJPAKE_WITH_AES_128_CCM_8"
    cuiteTable[0xC100] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"
    cuiteTable[0xC101] = "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"
    cuiteTable[0xC102] = "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
    cuiteTable[0xC103] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"
    cuiteTable[0xC104] = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"
    cuiteTable[0xC105] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"
    cuiteTable[0xC106] = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"
    cuiteTable[0xCACA] = "Reserved (GREASE)"
    cuiteTable[0xCC13] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCC14] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCC15] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCA8] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCA9] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAA] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAB] = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAC] = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAD] = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xCCAE] = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"
    cuiteTable[0xD001] = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"
    cuiteTable[0xD002] = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"
    cuiteTable[0xD003] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"
    cuiteTable[0xD005] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"
    cuiteTable[0xDADA] = "Reserved (GREASE)"
    cuiteTable[0xE410] = "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE411] = "TLS_RSA_WITH_SALSA20_SHA1"
    cuiteTable[0xE412] = "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE413] = "TLS_ECDHE_RSA_WITH_SALSA20_SHA1"
    cuiteTable[0xE414] = "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE415] = "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1"
    cuiteTable[0xE416] = "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE417] = "TLS_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE418] = "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE419] = "TLS_ECDHE_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE41A] = "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE41B] = "TLS_RSA_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE41C] = "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE41D] = "TLS_DHE_PSK_WITH_SALSA20_SHA1"
    cuiteTable[0xE41E] = "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1"
    cuiteTable[0xE41F] = "TLS_DHE_RSA_WITH_SALSA20_SHA1"
    cuiteTable[0xEAEA] = "Reserved (GREASE)"
    cuiteTable[0xFAFA] = "Reserved (GREASE)"
    cuiteTable[0xfefe] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
    cuiteTable[0xfeff] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xffe0] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
    cuiteTable[0xffe1] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
    cuiteTable[0xE001] = "TLS1_CK_ECDHE_WITH_SM1_SM3"
    cuiteTable[0xE003] = "TLS1_CK_ECDHE_WITH_SM1_SM3"
    cuiteTable[0xE005] = "TLS1_CK_ECC_WITH_SM1_SM3"
    cuiteTable[0xE007] = "TLS1_CK_IBC_WITH_SM1_SM3"
    cuiteTable[0xE009] = "TLS1_CK_RSA_WITH_SM1_SM3"
    cuiteTable[0xE00A] = "TLS1_CK_RSA_WITH_SM1_SHA1"
    cuiteTable[0xE011] = "TLS1_CK_ECDHE_WITH_SM4_SM3"
    cuiteTable[0xE013] = "TLS1_CK_ECC_WITH_SM4_SM3"
    cuiteTable[0xE015] = "TLS1_CK_IBSDH_WITH_SM4_SM3"
    cuiteTable[0xE017] = "TLS1_CK_IBC_WITH_SM4_SM3"
    cuiteTable[0xE019] = "TLS1_CK_RSA_WITH_SM4_SM3"
	cuiteTable[0xE01A] = "TLS1_CK_RSA_WITH_SM4_SHA1"
	
	local retStr = cuiteTable[cuiteId]
	if (retStr == nil)
	then
		return "NotFound CipherSuite"
	end
	return retStr
end
-- register this dissector
DissectorTable.get("tcp.port"):add(PORT, GMSSL)