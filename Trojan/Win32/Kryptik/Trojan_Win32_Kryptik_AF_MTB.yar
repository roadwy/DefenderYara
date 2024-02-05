
rule Trojan_Win32_Kryptik_AF_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.AF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 cc 6b 55 ec 00 8b 45 f4 2b c2 03 45 dc 2b 45 ec 05 99 14 00 00 33 45 fc 89 45 e4 0f b6 4d e0 03 4d f0 0f b6 55 f0 03 ca 83 e1 00 0f b7 45 e4 0b c8 89 4d dc 83 7d e8 00 75 09 } //01 00 
		$a_01_1 = {0f b7 45 fc 0f b7 4d e4 83 e1 00 33 4d f8 0b c1 89 45 dc 8b 55 f0 83 c2 1f 89 55 f0 6b 45 dc 00 0f b6 55 f8 8b 4d e4 03 4d d8 03 4d d4 0f b6 75 e0 2b ce d3 e2 33 c2 66 89 45 f4 6b 45 f8 00 89 45 f4 81 7d f0 0a 03 00 00 72 b5 } //00 00 
	condition:
		any of ($a_*)
 
}