
rule Trojan_Win64_BumbleBee_ME_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 8b 85 c8 03 00 00 81 f1 cf 30 00 00 44 2b d1 41 8b ca d3 ea 8a 88 e0 01 00 00 49 8b 45 40 80 f1 38 22 d1 49 63 8d b0 03 00 00 88 14 01 41 ff 85 b0 03 00 00 45 85 d2 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}