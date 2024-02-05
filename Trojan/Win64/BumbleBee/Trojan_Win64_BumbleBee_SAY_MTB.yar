
rule Trojan_Win64_BumbleBee_SAY_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c1 41 90 01 06 41 90 01 06 41 90 01 03 41 90 01 06 83 e8 90 01 01 41 90 01 03 49 90 01 03 49 90 01 03 46 90 01 03 49 90 01 03 45 90 01 04 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}