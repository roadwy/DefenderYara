
rule Trojan_Win64_Wineloader_A{
	meta:
		description = "Trojan:Win64/Wineloader.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 00 01 00 00 99 f7 f9 8b 44 24 90 01 01 48 63 d2 90 01 07 0f b6 0c 11 01 c8 88 c1 48 8b 44 24 90 00 } //01 00 
		$a_03_1 = {48 8b 44 24 90 01 01 0f b6 00 3d ff 00 00 00 90 00 } //01 00 
		$a_03_2 = {48 83 ec 08 90 01 07 48 c7 c2 28 80 00 00 e8 90 00 } //01 00 
		$a_03_3 = {48 89 05 30 8e 00 00 48 c7 05 90 01 08 48 c7 05 90 01 08 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}