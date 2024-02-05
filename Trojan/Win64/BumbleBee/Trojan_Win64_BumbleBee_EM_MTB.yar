
rule Trojan_Win64_BumbleBee_EM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 89 c4 00 00 00 0f af c8 8b c1 48 8b 8c 24 20 01 00 00 89 81 c4 00 00 00 8b 44 24 5c 0f af 44 24 54 0f af 44 24 50 48 8b 8c 24 20 01 00 00 8b 89 } //00 00 
	condition:
		any of ($a_*)
 
}