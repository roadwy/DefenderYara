
rule Trojan_Win64_BazarLoader_QC_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 95 48 8b 2b 48 95 48 85 c0 0f 84 05 00 00 00 4d 87 ff ff d0 } //5
		$a_01_1 = {48 c1 e2 07 48 c1 e2 0c 48 c1 e2 06 48 c1 e2 03 48 d1 e2 48 c1 e2 03 48 0b c2 c7 44 24 c4 32 48 bc 6d } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}