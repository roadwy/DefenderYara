
rule HackTool_Win32_NslookupLdap_A{
	meta:
		description = "HackTool:Win32/NslookupLdap.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 } //01 00 
		$a_00_1 = {2d 00 71 00 75 00 65 00 72 00 79 00 74 00 79 00 70 00 65 00 3d 00 61 00 6c 00 6c 00 } //01 00 
		$a_00_2 = {2d 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 3d 00 } //01 00 
		$a_00_3 = {5f 00 6c 00 64 00 61 00 70 00 2e 00 5f 00 74 00 63 00 70 00 2e 00 64 00 63 00 2e 00 5f 00 6d 00 73 00 64 00 63 00 73 00 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}