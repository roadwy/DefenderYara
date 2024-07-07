
rule Trojan_Win64_BazarLoader_DG_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 28 c1 e8 10 8b 4c 24 34 83 c1 01 89 8c 24 a4 00 00 00 48 8b 4c 24 50 48 8b 94 24 90 00 00 00 88 04 11 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}