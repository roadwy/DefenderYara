
rule Trojan_Win32_NSISInject_ES_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 57 ff 15 } //05 00 
		$a_01_1 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15 } //01 00 
		$a_03_2 = {fe 04 01 8b 0c 24 80 04 01 90 01 01 39 c5 74 90 01 01 8b 3c 24 40 eb 90 01 01 8b 04 24 ff e0 83 c4 0c 5e 5f 5b 5d c3 90 00 } //01 00 
		$a_03_3 = {8b 45 f8 03 45 fc 0f b6 08 90 02 06 8b 55 f8 03 55 fc 88 0a e9 90 01 04 8b 45 f8 ff e0 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}