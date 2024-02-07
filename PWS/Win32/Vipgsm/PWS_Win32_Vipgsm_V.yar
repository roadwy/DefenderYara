
rule PWS_Win32_Vipgsm_V{
	meta:
		description = "PWS:Win32/Vipgsm.V,SIGNATURE_TYPE_PEHSTR,12 00 12 00 12 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 } //01 00  kaspersky-labs
		$a_01_1 = {76 69 72 75 73 6c 69 73 74 } //01 00  viruslist
		$a_01_2 = {73 79 6d 61 74 65 63 } //01 00  symatec
		$a_01_3 = {75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 } //01 00  update.symantec
		$a_01_4 = {73 79 6d 61 6e 74 65 63 6c 69 76 65 75 70 64 61 74 65 } //01 00  symantecliveupdate
		$a_01_5 = {73 6f 70 68 6f 73 } //01 00  sophos
		$a_01_6 = {6e 6f 72 74 6f 6e } //01 00  norton
		$a_01_7 = {6d 63 61 66 65 65 } //01 00  mcafee
		$a_01_8 = {6c 69 76 65 75 70 64 61 74 65 2e 73 79 6d 61 6e 74 65 63 6c 69 76 65 75 70 64 61 74 65 } //01 00  liveupdate.symantecliveupdate
		$a_01_9 = {66 2d 73 65 63 75 72 65 } //01 00  f-secure
		$a_01_10 = {73 65 63 75 72 65 2e 6e 61 69 } //01 00  secure.nai
		$a_01_11 = {6d 79 2d 65 74 72 75 73 74 } //01 00  my-etrust
		$a_01_12 = {6e 65 74 77 6f 72 6b 61 73 73 6f 63 69 61 74 65 73 } //01 00  networkassociates
		$a_01_13 = {74 72 65 6e 64 6d 69 63 72 6f } //01 00  trendmicro
		$a_01_14 = {67 72 69 73 6f 66 74 } //01 00  grisoft
		$a_01_15 = {73 61 6e 64 62 6f 78 2e 6e 6f 72 6d 61 6e } //01 00  sandbox.norman
		$a_01_16 = {75 6b 2e 74 72 65 6e 64 6d 69 63 72 6f 2d 65 75 72 6f 70 65 } //01 00  uk.trendmicro-europe
		$a_01_17 = {54 63 70 43 68 65 63 6b 49 6e 69 74 } //00 00  TcpCheckInit
	condition:
		any of ($a_*)
 
}