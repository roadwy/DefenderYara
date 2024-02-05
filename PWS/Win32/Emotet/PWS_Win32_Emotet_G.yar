
rule PWS_Win32_Emotet_G{
	meta:
		description = "PWS:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 32 31 32 2e 37 31 2e 32 35 35 2e 90 02 03 3a 34 34 33 2f 90 02 20 2f 73 6d 74 70 2e 70 68 70 90 00 } //0a 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 39 34 2e 31 37 36 2e 32 2e 90 02 03 3a 34 34 33 2f 90 02 20 2f 73 6d 74 70 2e 70 68 70 90 00 } //01 00 
		$a_01_2 = {2f 73 78 6d 6c } //01 00 
		$a_01_3 = {22 25 73 22 20 2f 63 20 22 25 73 22 } //01 00 
		$a_01_4 = {22 25 73 22 20 25 73 20 22 25 73 22 } //01 00 
		$a_01_5 = {43 6f 6d 53 70 65 63 } //00 00 
		$a_00_6 = {5d 04 00 00 } //a4 39 
	condition:
		any of ($a_*)
 
}