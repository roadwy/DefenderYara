
rule Trojan_Win64_BumbleBee_SAC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c1 89 43 90 01 01 8b 83 90 01 04 05 90 01 04 01 43 90 01 01 8b 8b 90 01 04 8d 41 90 01 01 31 43 90 01 01 8d 04 4d 90 01 04 89 83 90 01 04 8b 43 90 01 01 48 90 01 06 31 04 11 48 90 01 03 8b 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}