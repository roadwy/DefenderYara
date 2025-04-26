
rule Backdoor_Win64_Drixed_Q_MTB{
	meta:
		description = "Backdoor:Win64/Drixed.Q!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 5c 24 28 43 8a 1c 13 45 89 c0 44 89 c6 2a 1c 31 48 8b 4c 24 18 42 88 1c 11 01 d0 8b 54 24 24 39 d0 89 44 24 04 } //10
		$a_01_1 = {4c 8b 44 24 30 4c 8b 4c 24 30 4c 8b 54 24 10 47 8a 1c 02 4c 8b 04 24 47 88 1c 08 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}