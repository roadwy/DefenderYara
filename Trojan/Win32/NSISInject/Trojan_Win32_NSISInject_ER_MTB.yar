
rule Trojan_Win32_NSISInject_ER_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 55 } //05 00 
		$a_01_1 = {89 54 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d b8 ff d0 } //01 00 
		$a_03_2 = {8b 4d f8 03 4d fc 0f b6 11 90 02 06 8b 45 f8 03 45 fc 88 10 e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //01 00 
		$a_03_3 = {88 14 08 8b 45 d4 83 c0 01 89 45 d4 e9 90 01 04 8b 45 e4 ff e0 83 c4 5c 5e 5f 5b 5d c2 10 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}