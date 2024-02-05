
rule Trojan_Win32_Citadel_MB_MTB{
	meta:
		description = "Trojan:Win32/Citadel.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 55 e8 29 d2 88 55 e8 0f b7 45 e4 c1 e0 10 89 45 e0 8b 45 e0 c1 e8 03 66 89 45 e4 0f b6 55 e8 33 55 e0 81 ea 90 01 04 0f b6 0b 8b 45 f8 88 0c 10 0f b6 55 e8 0f b7 4d e4 09 ca 81 f2 90 01 04 88 55 dc 66 81 7d e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}