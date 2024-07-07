
rule Backdoor_Win32_Brambul_A{
	meta:
		description = "Backdoor:Win32/Brambul.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 ba 00 00 00 66 c7 44 24 04 02 00 c7 44 24 08 00 00 00 00 } //1
		$a_01_1 = {83 f8 ff 75 08 c7 44 24 18 34 42 4d 53 8b 4c 24 18 81 e9 31 42 4d 53 } //1
		$a_01_2 = {b3 63 bf 01 00 00 00 c6 44 24 0d 3a c6 44 24 0e 5c } //1
		$a_01_3 = {ff d6 48 83 f8 05 77 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}