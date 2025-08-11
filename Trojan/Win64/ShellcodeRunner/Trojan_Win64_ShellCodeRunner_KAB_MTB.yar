
rule Trojan_Win64_ShellCodeRunner_KAB_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 48 8d 45 a0 b9 20 08 00 00 4c 8b 00 4c 89 02 41 89 c8 49 01 d0 4d 8d 48 08 41 89 c8 49 01 c0 49 83 c0 08 4d 8b 40 f0 4d 89 41 f0 4c 8d 42 08 49 83 e0 f8 4c 29 c2 48 29 d0 01 d1 83 e1 f8 c1 e9 03 89 ca 89 d2 4c 89 c7 48 89 c6 48 89 d1 f3 48 a5 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}