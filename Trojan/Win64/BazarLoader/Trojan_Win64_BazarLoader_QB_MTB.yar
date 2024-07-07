
rule Trojan_Win64_BazarLoader_QB_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 32 8a 44 24 32 f6 e1 88 44 24 32 8b 44 24 2c 8b 44 24 48 0f af 44 24 54 89 44 24 50 8b 44 24 2c 8b 44 24 2c 01 44 24 50 8b 44 24 2c 8b 44 24 50 48 8b 8c 24 80 00 00 00 8a 04 01 88 44 24 3a 8b 44 24 2c 8a 44 24 3a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}