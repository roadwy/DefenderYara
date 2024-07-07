
rule Backdoor_Win32_Farfli_ABM_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.ABM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 8b 06 8b c8 25 ff 0f 00 00 c1 e9 0c } //10
		$a_01_1 = {8b 4d 0c 01 0c 18 8b 42 04 47 83 e8 08 83 c6 02 d1 e8 3b f8 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}