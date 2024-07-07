
rule Trojan_Win32_Upatre_AA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 57 8b f9 2b c9 ac 50 8b 07 8a c8 8b c1 47 58 3b c1 } //10
		$a_01_1 = {8b 56 08 6b c0 2c 89 4c 10 1c 8b 06 8b 56 08 6b c0 2c 89 4c 10 20 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}