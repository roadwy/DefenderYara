
rule Trojan_Win32_Waski_AA_MTB{
	meta:
		description = "Trojan:Win32/Waski.AA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 75 f4 33 c0 21 45 fc 8b 75 0c 8b c8 41 ac 85 c0 75 fa } //10
		$a_01_1 = {03 f0 47 51 33 c0 56 8b c8 ac 41 85 c0 75 fa } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}