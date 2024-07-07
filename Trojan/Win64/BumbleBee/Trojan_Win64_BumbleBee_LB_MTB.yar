
rule Trojan_Win64_BumbleBee_LB_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.LB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 45 08 49 8b 95 90 01 04 48 69 88 90 01 08 48 01 8a 90 01 04 49 8b 45 90 01 01 49 8b 8d 90 01 04 48 81 f1 90 01 04 48 89 88 90 01 04 49 8b 8d 90 01 04 48 69 81 90 01 08 48 89 81 90 01 04 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}