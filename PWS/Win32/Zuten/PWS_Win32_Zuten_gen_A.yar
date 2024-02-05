
rule PWS_Win32_Zuten_gen_A{
	meta:
		description = "PWS:Win32/Zuten.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 05 00 "
		
	strings :
		$a_02_0 = {6a fc 56 ff d7 8b 1d 90 01 04 8d 55 f8 6a 00 52 8d 45 f4 6a 04 50 56 ff d3 81 7d f4 fc fd fe ff 74 10 56 ff 15 90 00 } //04 00 
		$a_00_1 = {85 db 74 18 8a 06 8a 0f d2 c0 88 06 46 47 4b 4a 85 d2 75 ec } //01 00 
		$a_02_2 = {6a 04 52 53 c7 45 90 01 01 fc fd fe ff ff d6 53 ff 15 90 00 } //01 00 
		$a_03_3 = {6a 04 50 56 ff d3 81 7c 24 90 01 01 fc fd fe ff 74 11 56 ff 15 90 00 } //01 00 
		$a_01_4 = {6a 04 52 53 ff d7 8b 44 24 14 6a 02 3d fc fd fe ff } //00 00 
	condition:
		any of ($a_*)
 
}