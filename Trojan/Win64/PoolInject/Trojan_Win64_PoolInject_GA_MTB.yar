
rule Trojan_Win64_PoolInject_GA_MTB{
	meta:
		description = "Trojan:Win64/PoolInject.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 28 33 c8 8b c1 89 44 24 24 8b 44 24 2c 89 44 24 28 eb b9 } //3
		$a_01_1 = {0f b6 c8 48 8b 44 24 38 48 d3 e8 48 25 ff 00 00 00 48 63 4c 24 24 48 8b 54 24 28 48 03 d1 48 8b ca 48 8b 54 24 30 88 04 0a } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=3
 
}