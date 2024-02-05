
rule Trojan_Win32_Zloader_GA_MTB{
	meta:
		description = "Trojan:Win32/Zloader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {8a 0c 32 88 0c 38 8b 55 90 01 01 83 c2 90 01 01 89 55 90 02 0f 5f 5e 8b e5 5d c3 90 0a 32 00 03 45 90 01 01 8b 90 00 } //05 00 
		$a_02_1 = {03 01 8b 55 90 01 01 89 02 8b 45 90 01 01 8b 08 83 e9 90 01 01 8b 55 90 01 01 89 0a 8b e5 5d c3 90 00 } //0a 00 
		$a_02_2 = {8b c2 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 0a 32 00 90 17 04 01 01 01 01 31 32 30 33 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 f0 67 04 80 5c 28 } //00 00 
	condition:
		any of ($a_*)
 
}