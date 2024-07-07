
rule Trojan_Win64_BumbleBee_CAFK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.CAFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 63 5c 24 08 43 0f b6 0c 19 89 ca 83 f2 ff 81 e2 90 01 04 be 90 01 04 81 f6 90 01 04 21 f1 89 c7 83 f7 ff 81 e7 90 01 04 21 f0 09 ca 09 c7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}