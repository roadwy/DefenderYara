
rule PWS_Win32_Tibia_AS{
	meta:
		description = "PWS:Win32/Tibia.AS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 69 62 69 61 63 6c 69 65 6e 74 00 } //01 00 
		$a_00_1 = {63 3a 5c 66 76 72 33 32 2e 63 6f 6d 00 } //01 00 
		$a_01_2 = {33 d2 8a 54 1f ff 03 d3 f7 d2 88 54 18 ff 43 4e 75 e7 } //01 00 
		$a_03_3 = {b3 ff 8d b5 90 01 04 8d 85 90 01 04 8a 16 e8 90 01 04 8b 95 90 01 04 8b c7 e8 90 01 04 46 fe cb 75 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}