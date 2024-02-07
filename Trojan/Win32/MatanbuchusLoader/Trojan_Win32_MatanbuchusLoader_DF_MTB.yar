
rule Trojan_Win32_MatanbuchusLoader_DF_MTB{
	meta:
		description = "Trojan:Win32/MatanbuchusLoader.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 30 4b 75 51 6b 41 32 2e 64 6c 6c } //01 00  a0KuQkA2.dll
		$a_01_1 = {41 35 32 65 51 61 } //01 00  A52eQa
		$a_01_2 = {43 31 6c 79 48 6a 76 4f 42 39 } //01 00  C1lyHjvOB9
		$a_01_3 = {44 4b 30 56 45 61 } //01 00  DK0VEa
		$a_01_4 = {4b 5a 49 79 39 76 4a 30 30 } //01 00  KZIy9vJ00
		$a_01_5 = {53 42 50 54 43 36 45 42 69 } //01 00  SBPTC6EBi
		$a_01_6 = {55 33 57 36 69 68 70 63 } //00 00  U3W6ihpc
	condition:
		any of ($a_*)
 
}