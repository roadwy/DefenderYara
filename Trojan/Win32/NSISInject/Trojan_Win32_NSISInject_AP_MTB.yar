
rule Trojan_Win32_NSISInject_AP_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 99 b9 0c 00 00 00 f7 f9 8b 85 54 ff ff ff 0f b6 0c 10 8b 55 dc 03 55 f4 0f b6 02 33 c1 8b 4d dc 03 4d f4 88 01 eb } //01 00 
		$a_03_1 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 d0 52 6a 00 ff 15 90 02 04 89 45 dc 8b 45 d4 50 6a 01 8b 4d d0 51 8b 55 dc 52 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}