class SMB_HEADER(Structure):
	_pack_ = 1

	_fields_ = [
	("server_component", c_uint32),
	("smb_command", c_uint8),
	("error_class", c_uint8),
	("reserved1", c_uint8),
	("error_code", c_uint16),
	("flags", c_uint8),
	("flags2", c_uint16),
	("process_id_high", c_uint16),
	("signature", c_uint64),
	("reserved2", c_uint16),
	("tree_id", c_uint16),
	("process_id", c_uint16),
	("user_id", c_uint16),
	("multiplex_id", c_uint16)

	("WordCount", c_uint8),
	("TotalParameterCount", c_uint16),
	("TotalDataCount", c_uint16),
	("MaxParameterCount", c_uint16),
	("MaxDataCount", c_uint16),
	("MaxSetupCount", c_uint8),
	("reserved", c_uint8),
	("flags", c_uint16),
	("timeout", c_uint32),
	("reserved2", c_uint16),
	("ParameterCount", c_uint16),
	("ParameterOffset", c_uint16),
	("DataCount", c_uint16),
	("DataOffset", c_uint16),
	("SetupCount", c_uint8),
	("reserved3", c_uint8),
	("SubCommand", c_uint16),  #Function
	("ByteCount", c_uint16),
	("padding", c_uint8),
	("padding2", c_uint16),

  #figure this out to convert this from C to Python
	#uint8 parameters[12]
	#uint8 SMBData[4096]
