
rule Trojan_Win64_BazaarLoader_CCGN_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.CCGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 f9 48 c7 c2 04 00 00 00 49 c7 c0 90 01 01 ff ff ff 49 81 c0 90 01 04 6a 00 6a 00 4c 8d 0c 24 c8 60 00 00 ff 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}