
rule PWS_Win32_QQpass_CIM{
	meta:
		description = "PWS:Win32/QQpass.CIM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 3a 5c 66 64 73 66 2e 62 6d 70 } //01 00 
		$a_01_1 = {4a 6f 61 63 68 69 6d 50 65 69 70 65 72 2e 64 61 74 } //01 00 
		$a_01_2 = {49 57 49 4c 4c 4b 49 4c 4c 59 4f 55 00 00 00 00 45 58 50 4c 4f 50 45 52 2e 65 78 65 } //01 00 
		$a_01_3 = {72 77 79 65 72 77 65 69 75 72 65 72 00 00 00 00 68 68 68 68 68 68 68 68 68 68 68 68 } //00 00 
	condition:
		any of ($a_*)
 
}