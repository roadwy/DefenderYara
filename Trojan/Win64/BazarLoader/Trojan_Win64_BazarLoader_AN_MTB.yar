
rule Trojan_Win64_BazarLoader_AN_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 09 89 ca f6 d2 20 c2 f6 d0 20 c8 08 d0 48 8b 4d 90 01 01 88 01 48 8b 45 90 01 01 0f b6 00 04 01 48 8b 4d 90 01 01 88 01 90 0a 2f 00 48 8b 45 90 01 01 0f b6 00 48 8b 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}