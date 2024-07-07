
rule Trojan_Win64_BumbleBee_SAV_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 31 8b 90 01 04 8b 4b 90 01 01 48 90 01 06 81 c1 90 01 04 03 d1 45 90 01 03 49 90 01 03 8b 83 90 01 04 44 90 01 04 0f af c2 41 90 01 02 89 83 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}