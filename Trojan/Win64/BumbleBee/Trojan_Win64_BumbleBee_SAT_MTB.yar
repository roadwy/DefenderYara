
rule Trojan_Win64_BumbleBee_SAT_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 31 4b 90 01 01 8b 83 90 01 04 8b 4b 90 01 01 05 90 01 04 03 4b 90 01 01 03 c8 48 90 01 06 48 90 01 06 45 90 01 02 89 4b 90 01 01 8b 83 90 01 04 03 43 90 01 01 35 90 01 04 09 43 90 01 01 8b 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}