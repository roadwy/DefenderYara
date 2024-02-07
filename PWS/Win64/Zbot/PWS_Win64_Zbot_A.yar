
rule PWS_Win64_Zbot_A{
	meta:
		description = "PWS:Win64/Zbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 83 39 2d 75 90 01 01 0f b7 41 02 83 f8 66 74 90 01 01 83 f8 69 74 90 00 } //01 00 
		$a_01_1 = {42 8a 04 09 43 88 04 08 42 88 14 09 43 0f b6 0c 08 03 ca 0f b6 c1 42 8a 0c 08 30 0b 48 ff c3 48 ff cf 75 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}