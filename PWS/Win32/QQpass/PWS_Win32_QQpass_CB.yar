
rule PWS_Win32_QQpass_CB{
	meta:
		description = "PWS:Win32/QQpass.CB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 11 32 45 d0 88 04 31 8b 4d cc 83 c1 01 } //01 00 
		$a_00_1 = {26 00 4b 00 69 00 6c 00 6c 00 53 00 6f 00 66 00 74 00 3d 00 00 00 } //01 00 
		$a_00_2 = {26 00 77 00 65 00 72 00 74 00 79 00 75 00 3d 00 00 00 } //01 00 
		$a_00_3 = {44 00 69 00 73 00 6b 00 4e 00 75 00 6d 00 62 00 65 00 72 00 3d 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}