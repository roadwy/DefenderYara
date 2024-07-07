
rule Trojan_Win64_BumbleBee_HM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 01 b8 90 01 04 ff 05 90 01 04 2b 83 90 01 04 2b 83 90 01 04 01 83 90 01 04 48 8b 43 90 01 01 48 63 0d 90 01 04 44 88 0c 01 ff 05 90 01 04 48 8b 15 90 01 04 8b 4a 90 01 01 33 8b 90 01 04 8b 82 90 01 04 81 e9 90 01 04 0f af c1 89 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}