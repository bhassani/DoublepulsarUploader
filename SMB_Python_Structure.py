structure = (
	#NetBIOS Header
	('SmbMessageType','<H=0'),
	('SmbMessageLength','<H=0'),

	#SMB Header
        ('Signature', '"\xffSMB'),
        ('Command','B=0'),
        ('ErrorClass','B=0'),
        ('_reserved','B=0'),
        ('ErrorCode','<H=0'),
        ('Flags1','B=0'),
        ('Flags2','<H=0'),
        ('PIDHigh','<H=0'),
        ('SecurityFeatures','8s=""'),
        ('Reserved','<H=0'),
        ('Tid','<H=0xffff'),
        ('Pid','<H=0'),
        ('Uid','<H=0'),
        ('Mid','<H=0'),

	#trans2 packet from Impacket
	('WordCount', 'B=len(Parameters)//2'),
	('TotalParameterCount','<H=0'),
  ('TotalDataCount','<H'),

	#added by me
	('MaxParameterCount','<H=0'), #maybe implement this way ? -> ('MaxParameterCount','B=0'),
	('MaxDataCount','<H=0'),      #maybe implement this way ? -> ('MaxDataCount','B=0'),
	('MaxSetupCount','<H=0'),     #maybe implement this way ? -> ('MaxSetupCount','B=0'),
	('Reserved1','<H=0'),
	('Flags3','<H=0'),
	('Timeout','<Q=0'),
	('Reserved2','<H=0'),

	#trans2 packet from Impacket
	('ParameterCount','<H=0'),
  ('ParameterOffset','<H=0'),
	('DataCount','<H'),
  ('DataOffset','<H'),

	#added by me
	('SetupCount','B=0'),
	('Reserved3','B=0'),
	('SubCommand','B=0'),

	#added by Impacket
	('ByteCount','<H-Data'),
	('Pad1',':'),
	('Parameters',':'),             # default set by constructor
  ('Data',':'),                   # default set by constructor

	)
