
rule Trojan_Win64_BumbleBee_SAI_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 43 70 48 90 01 06 2d 90 01 04 31 83 90 01 04 8b 43 90 01 01 2b 83 90 01 04 2d 90 01 04 01 43 90 01 01 48 90 01 06 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}