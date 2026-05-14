
rule Trojan_Win64_CobalStrike_ARA_MTB{
	meta:
		description = "Trojan:Win64/CobalStrike.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 d9 48 89 f7 83 e1 03 48 c1 e1 03 48 d3 ff 31 f8 88 44 1a 08 48 ff c3 e9 } //2
		$a_01_1 = {4c 89 c1 83 e1 03 48 c1 e1 03 49 d3 fe 44 31 f0 42 88 44 02 08 49 ff c0 e9 } //2
		$a_01_2 = {83 e1 03 48 c1 e1 03 49 d3 f9 48 8d 4c 24 50 44 31 c8 42 88 44 3a 08 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}