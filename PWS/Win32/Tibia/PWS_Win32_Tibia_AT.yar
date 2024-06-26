
rule PWS_Win32_Tibia_AT{
	meta:
		description = "PWS:Win32/Tibia.AT,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 03 00 "
		
	strings :
		$a_03_0 = {80 38 37 75 11 90 09 14 00 c7 00 90 01 01 00 00 00 8b c3 ba 90 01 04 e8 90 01 04 8b 03 90 00 } //03 00 
		$a_01_1 = {0f b6 44 10 ff 88 03 ff 45 f4 43 4e 75 d0 } //01 00 
		$a_00_2 = {47 00 45 00 54 00 20 00 2f 00 6e 00 65 00 77 00 72 00 2e 00 70 00 68 00 70 00 3f 00 } //01 00  GET /newr.php?
		$a_00_3 = {48 00 6f 00 73 00 74 00 3a 00 20 00 77 00 61 00 72 00 74 00 69 00 62 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } //01 00  Host: wartibia.com
		$a_02_4 = {2d 00 78 00 31 00 33 00 90 02 04 25 00 64 00 90 00 } //01 00 
		$a_01_5 = {38 37 2e 39 38 2e 31 34 31 2e 31 33 30 } //01 00  87.98.141.130
		$a_01_6 = {74 62 69 5f 72 65 61 64 65 64 5f 64 61 74 61 } //01 00  tbi_readed_data
		$a_01_7 = {74 62 69 5f 64 61 74 61 } //00 00  tbi_data
	condition:
		any of ($a_*)
 
}