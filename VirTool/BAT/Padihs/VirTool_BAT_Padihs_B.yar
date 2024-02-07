
rule VirTool_BAT_Padihs_B{
	meta:
		description = "VirTool:BAT/Padihs.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 48 00 54 00 54 00 50 00 20 00 57 00 65 00 62 00 20 00 50 00 72 00 6f 00 78 00 79 00 20 00 41 00 75 00 74 00 6f 00 2d 00 44 00 69 00 73 00 63 00 6f 00 76 00 65 00 72 00 79 00 } //01 00  WinHTTP Web Proxy Auto-Discovery
		$a_01_1 = {64 69 61 67 68 6f 73 2e 64 6c 6c 00 64 69 61 67 68 6f 73 00 3c 4d 6f 64 75 6c 65 3e } //01 00 
		$a_01_2 = {73 00 61 00 6e 00 64 00 62 00 6f 00 78 00 69 00 65 00 72 00 70 00 63 00 73 00 73 00 } //00 00  sandboxierpcss
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}