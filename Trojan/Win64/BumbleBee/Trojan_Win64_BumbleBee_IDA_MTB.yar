
rule Trojan_Win64_BumbleBee_IDA_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.IDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 0f 1f 44 00 00 8b 8b 90 01 04 8b 83 90 01 04 83 f1 90 01 01 0f af c1 48 63 4b 90 01 01 89 83 90 01 04 48 8b 43 90 01 01 45 8b 04 01 49 83 c1 90 01 01 44 0f af 43 90 01 01 48 8b 83 90 01 04 41 8b d0 c1 ea 90 01 01 88 14 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}