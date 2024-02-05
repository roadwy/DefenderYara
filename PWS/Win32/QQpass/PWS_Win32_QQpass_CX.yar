
rule PWS_Win32_QQpass_CX{
	meta:
		description = "PWS:Win32/QQpass.CX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {79 6f 75 6d 65 69 79 6f 75 67 61 6f 63 75 6f } //01 00 
		$a_00_1 = {5f 5f 5f 5f 41 56 50 2e 52 6f 6f 74 } //01 00 
		$a_01_2 = {53 79 73 57 46 47 77 64 2e 64 6c 6c } //01 00 
		$a_01_3 = {44 6f 77 6e 53 74 61 72 74 2e 74 78 74 } //01 00 
		$a_00_4 = {44 4c 4c 46 49 4c 45 } //01 00 
		$a_01_5 = {4a 6d 70 48 6f 6f 6b 4f 66 66 } //01 00 
		$a_01_6 = {4a 6d 70 48 6f 6f 6b 4f 6e } //01 00 
		$a_01_7 = {5a 58 59 5f 77 66 67 57 44 } //00 00 
	condition:
		any of ($a_*)
 
}