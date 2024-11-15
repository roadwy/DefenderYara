
rule Trojan_Win64_MintZard_A_MTB{
	meta:
		description = "Trojan:Win64/MintZard.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 c7 48 c7 c1 9a 8e 00 00 f3 a4 } //1
		$a_01_1 = {74 32 45 33 c0 48 83 7a 18 10 44 89 44 24 68 72 03 48 8b 12 4c 89 44 24 20 4c 8d 4c 24 68 44 8b c0 } //1
		$a_01_2 = {55 48 89 e5 48 83 ec 08 44 8b d2 41 81 f0 6e 74 65 6c b9 17 00 00 00 48 83 c0 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}