
rule Trojan_Win32_NSISInject_ET_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 55 } //05 00 
		$a_01_1 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15 } //05 00 
		$a_01_2 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 } //05 00 
		$a_01_3 = {6a 40 68 00 30 00 00 8b 55 ec 52 6a 00 ff 15 } //05 00 
		$a_01_4 = {6a 40 68 00 30 00 00 8b 45 e8 50 6a 00 ff 15 } //01 00 
		$a_03_5 = {8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //01 00 
		$a_03_6 = {8b 45 f8 03 45 fc 8a 08 80 c1 01 8b 55 f8 03 55 fc 88 0a e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //01 00 
		$a_03_7 = {8b 55 f8 03 55 fc 0f b6 02 90 02 06 8b 4d f8 03 4d fc 88 01 e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //01 00 
		$a_03_8 = {8b 45 f8 03 45 fc 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 ec 73 90 01 01 e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //01 00 
		$a_03_9 = {8b 4d f8 03 4d fc 0f b6 11 90 02 06 8b 45 f8 03 45 fc 88 10 e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}