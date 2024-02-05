
rule PWS_Win32_QQpass_FK{
	meta:
		description = "PWS:Win32/QQpass.FK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 6d 2e 65 78 65 00 00 71 71 2e 65 78 65 00 } //01 00 
		$a_00_1 = {5c 51 51 5c 52 65 67 69 73 74 72 79 2e 64 62 } //01 00 
		$a_00_2 = {26 71 71 70 61 73 73 77 6f 72 64 3d } //01 00 
		$a_03_3 = {8a 00 8b d5 88 01 41 5f 5d 84 c0 74 90 01 01 8a 02 88 01 41 42 84 c0 75 90 01 01 b1 6d b0 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}