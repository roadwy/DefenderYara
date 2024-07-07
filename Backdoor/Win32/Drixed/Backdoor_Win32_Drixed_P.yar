
rule Backdoor_Win32_Drixed_P{
	meta:
		description = "Backdoor:Win32/Drixed.P,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 ff 2d c4 25 b9 89 } //1
		$a_01_1 = {81 ff 9a 07 e2 13 89 } //1
		$a_01_2 = {b9 4d ac 70 b2 ba c9 3c 60 a6 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=100
 
}