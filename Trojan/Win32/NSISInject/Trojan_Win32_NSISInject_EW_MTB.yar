
rule Trojan_Win32_NSISInject_EW_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 68 eb 12 00 00 56 ff 15 } //01 00 
		$a_03_1 = {88 04 33 46 81 fe eb 12 00 00 72 90 01 01 6a 00 53 6a 00 ff 15 90 01 04 5f 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_EW_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 c4 08 89 c7 83 ec 10 66 0f 6f 05 00 20 40 00 f3 0f 7f 04 24 ff 15 } //0a 00 
		$a_01_1 = {83 c4 08 89 c7 83 ec 10 0f 28 05 00 20 40 00 0f 11 04 24 ff 15 } //0a 00 
		$a_01_2 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 } //01 00 
		$a_03_3 = {6a 00 56 6a 00 ff 15 90 01 02 40 00 83 c4 04 5e 5f c3 90 09 06 00 88 86 90 00 } //01 00 
		$a_03_4 = {83 c0 20 3d f0 12 00 00 75 90 01 01 6a 00 56 6a 00 ff 15 90 01 02 40 00 83 c4 04 5e 5f c3 90 00 } //01 00 
		$a_03_5 = {60 14 00 00 6a 00 56 6a 00 ff 15 90 01 02 40 00 83 c4 04 5e 5f c3 90 00 } //01 00 
		$a_03_6 = {8b 55 f8 03 55 fc 0f b6 02 90 02 06 8b 4d f8 03 4d fc 88 01 e9 90 02 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //01 00 
		$a_03_7 = {6a 00 56 6a 00 ff 15 90 01 02 40 00 83 c4 04 5e 5f c3 90 09 07 00 0f 7f 8e 90 00 } //01 00 
		$a_03_8 = {c1 f3 0f 7f 90 01 01 c0 13 00 00 6a 00 56 6a 00 ff 15 90 01 02 40 00 83 c4 04 5e 5f c3 90 00 } //01 00 
		$a_03_9 = {6a 00 56 6a 00 ff 15 90 01 02 40 00 83 c4 04 5e 5f c3 90 09 06 00 88 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}