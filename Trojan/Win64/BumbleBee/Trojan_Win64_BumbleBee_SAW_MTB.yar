
rule Trojan_Win64_BumbleBee_SAW_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c8 31 4b 90 01 01 8b 4b 90 01 01 8b 43 90 01 01 83 e9 90 01 01 0f af c1 41 90 01 02 c1 ea 90 01 01 89 43 90 00 } //01 00 
		$a_03_1 = {ff c1 0f af c1 8b 8b 90 01 04 81 c1 90 01 04 89 43 90 01 01 8b 83 90 01 04 0f af c1 89 83 90 01 04 49 90 01 06 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}