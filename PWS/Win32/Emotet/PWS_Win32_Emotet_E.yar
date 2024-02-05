
rule PWS_Win32_Emotet_E{
	meta:
		description = "PWS:Win32/Emotet.E,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6d 61 69 6c 70 76 2e 65 78 65 } //01 00 
		$a_01_1 = {5c 6d 61 69 6c 70 76 2e 63 66 67 } //01 00 
		$a_01_2 = {2f 73 78 6d 6c } //01 00 
		$a_01_3 = {2f 69 6e 2f 73 6d 74 70 2e 70 68 70 } //01 00 
		$a_03_4 = {6a 00 6a 1a 68 90 01 04 6a 00 ff 15 90 01 04 b8 90 01 04 c3 90 00 } //01 00 
		$a_03_5 = {6a 00 6a 1a 68 90 01 04 6a 00 ff d7 90 00 } //0a 00 
		$a_03_6 = {b8 1f 85 eb 51 f7 64 24 90 01 01 c1 ea 05 83 fa 02 74 07 b8 02 00 00 00 eb 11 56 8b 35 90 01 04 ff d6 57 ff d6 53 ff d6 33 c0 90 00 } //00 00 
		$a_00_7 = {80 10 00 00 a4 78 d3 fc 54 05 d8 1f } //ad 63 
	condition:
		any of ($a_*)
 
}