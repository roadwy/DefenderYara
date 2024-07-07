
rule Trojan_Win64_BazarLoader_QE_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 37 41 88 c1 41 28 c9 88 c1 80 e9 01 41 00 c9 44 28 c8 88 44 24 37 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_BazarLoader_QE_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QE!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c 0a 88 44 0d 87 48 ff c1 48 83 f9 0d 72 ec } //10
		$a_01_1 = {0f b6 44 15 b7 8d 4a 4f 32 c8 88 4c 15 b7 48 ff c2 48 83 fa 0c 72 e9 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}