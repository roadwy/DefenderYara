
rule Trojan_Win32_NSISInject_AQ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e0 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb } //01 00 
		$a_03_1 = {89 45 f0 6a 00 6a 00 8b 4d f4 51 e8 90 02 04 83 c4 0c 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}