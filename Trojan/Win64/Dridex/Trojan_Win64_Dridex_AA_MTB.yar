
rule Trojan_Win64_Dridex_AA_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 20 48 8b 54 24 28 4c 8b 44 24 18 45 8a 0c 00 48 8b 44 24 08 44 88 0c 10 48 8b 54 24 28 48 83 c2 01 48 89 54 24 38 4c 8b 54 24 10 4c 39 d2 } //10
		$a_01_1 = {83 e2 1f 89 d2 41 89 d0 8b 54 24 4c 89 54 24 4c 89 c2 41 89 d1 4c 8b 54 24 30 47 8a 1c 0a 46 2a 1c 01 48 8b 4c 24 20 46 88 1c 09 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}