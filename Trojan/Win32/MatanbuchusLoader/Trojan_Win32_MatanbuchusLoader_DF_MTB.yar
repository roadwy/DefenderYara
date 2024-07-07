
rule Trojan_Win32_MatanbuchusLoader_DF_MTB{
	meta:
		description = "Trojan:Win32/MatanbuchusLoader.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 30 4b 75 51 6b 41 32 2e 64 6c 6c } //2 a0KuQkA2.dll
		$a_01_1 = {41 35 32 65 51 61 } //1 A52eQa
		$a_01_2 = {43 31 6c 79 48 6a 76 4f 42 39 } //1 C1lyHjvOB9
		$a_01_3 = {44 4b 30 56 45 61 } //1 DK0VEa
		$a_01_4 = {4b 5a 49 79 39 76 4a 30 30 } //1 KZIy9vJ00
		$a_01_5 = {53 42 50 54 43 36 45 42 69 } //1 SBPTC6EBi
		$a_01_6 = {55 33 57 36 69 68 70 63 } //1 U3W6ihpc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}