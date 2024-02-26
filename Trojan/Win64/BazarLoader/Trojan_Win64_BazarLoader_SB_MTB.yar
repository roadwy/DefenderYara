
rule Trojan_Win64_BazarLoader_SB_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 45 d8 41 8b 4e 90 01 01 4c 8d 8c 24 90 01 04 41 8b 56 90 01 01 8b c3 0f ba e8 90 01 01 41 81 e0 90 01 04 0f 44 c3 48 03 ce 44 8b c0 8b d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}