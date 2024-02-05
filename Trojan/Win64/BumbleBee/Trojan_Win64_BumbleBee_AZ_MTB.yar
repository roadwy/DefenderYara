
rule Trojan_Win64_BumbleBee_AZ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 8b 04 01 49 83 c1 04 44 0f af 83 90 00 00 00 48 8b 83 08 01 00 00 41 8b d0 c1 ea 10 88 14 01 } //00 00 
	condition:
		any of ($a_*)
 
}