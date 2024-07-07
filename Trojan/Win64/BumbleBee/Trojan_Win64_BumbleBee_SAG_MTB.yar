
rule Trojan_Win64_BumbleBee_SAG_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 33 8b 90 01 04 2b 83 90 01 04 81 e9 90 01 04 01 83 90 01 04 8b 03 8b 93 90 01 04 33 93 90 01 04 0f af c1 81 ea 90 01 04 01 93 90 01 04 89 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}