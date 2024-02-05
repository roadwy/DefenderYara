
rule Trojan_Win32_Amadey_BAH_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {c1 e0 02 01 d0 c1 e0 03 89 c6 8b 45 08 8b 40 3c 89 c2 8b 45 08 01 c2 8b 45 08 8b 40 3c 89 c7 8b 45 08 01 f8 0f b7 40 14 } //02 00 
		$a_01_1 = {8b 45 08 8b 40 3c 89 c2 8b 45 08 01 d0 8b 40 50 c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 89 44 24 04 c7 04 24 00 00 00 00 e8 } //00 00 
	condition:
		any of ($a_*)
 
}