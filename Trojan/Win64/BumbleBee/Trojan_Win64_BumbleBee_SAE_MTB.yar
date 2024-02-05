
rule Trojan_Win64_BumbleBee_SAE_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c1 48 8b 8b 90 01 04 01 43 90 01 01 8b 83 90 01 04 42 90 01 03 49 83 c0 90 01 01 8b 8b 90 01 04 8b 83 90 01 04 33 43 90 01 01 83 f0 90 01 01 89 43 90 01 01 8b 83 90 01 04 01 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}