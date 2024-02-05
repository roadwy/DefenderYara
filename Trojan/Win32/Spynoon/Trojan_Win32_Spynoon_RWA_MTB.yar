
rule Trojan_Win32_Spynoon_RWA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 90 01 01 33 d2 b9 0a 00 00 00 f7 f1 0f b6 92 90 01 04 8b 45 90 01 01 03 45 90 01 01 0f b6 08 33 ca 8b 55 90 01 01 03 55 90 01 01 88 0a 8b 45 90 01 01 8b 08 83 c1 01 8b 55 90 01 01 89 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}