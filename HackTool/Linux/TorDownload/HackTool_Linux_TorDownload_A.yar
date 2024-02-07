
rule HackTool_Linux_TorDownload_A{
	meta:
		description = "HackTool:Linux/TorDownload.A,SIGNATURE_TYPE_CMDHSTR_EXT,3d 00 3d 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 } //0a 00  curl
		$a_00_1 = {77 00 67 00 65 00 74 00 } //32 00  wget
		$a_02_2 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 90 09 38 00 90 23 38 09 61 2d 7a 41 2d 5a 30 2d 39 90 00 } //01 00 
		$a_02_3 = {73 00 6f 00 63 00 6b 00 73 00 90 23 01 02 34 35 90 00 } //01 00 
		$a_00_4 = {75 00 73 00 65 00 77 00 69 00 74 00 68 00 74 00 6f 00 72 00 } //01 00  usewithtor
		$a_00_5 = {74 00 6f 00 72 00 73 00 6f 00 63 00 6b 00 73 00 } //01 00  torsocks
		$a_00_6 = {74 00 6f 00 72 00 69 00 66 00 79 00 } //01 00  torify
		$a_00_7 = {74 00 6f 00 72 00 32 00 77 00 65 00 62 00 } //01 00  tor2web
		$a_00_8 = {74 00 6f 00 72 00 32 00 73 00 6f 00 63 00 6b 00 73 00 } //00 00  tor2socks
	condition:
		any of ($a_*)
 
}