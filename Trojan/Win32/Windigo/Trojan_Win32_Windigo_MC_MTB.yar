
rule Trojan_Win32_Windigo_MC_MTB{
	meta:
		description = "Trojan:Win32/Windigo.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 46 53 77 7a 30 4a 6a 4a 61 76 5a 6c 54 61 45 48 38 73 72 } //5 nFSwz0JjJavZlTaEH8sr
		$a_01_1 = {2f 51 65 4c 51 6e 2d 6c 47 51 50 56 65 48 56 34 5f 56 52 48 71 2f 63 42 41 4b 75 75 77 42 44 70 55 39 54 46 6c 62 7a 79 31 73 } //5 /QeLQn-lGQPVeHV4_VRHq/cBAKuuwBDpU9TFlbzy1s
		$a_01_2 = {2f 32 7a 6d 67 37 78 71 6a 31 75 32 46 2d 44 30 52 4a 71 5a 45 } //5 /2zmg7xqj1u2F-D0RJqZE
		$a_01_3 = {b4 bf 9e 76 d0 03 9f 76 5a 53 9f 76 27 19 9e 76 c0 50 9d 76 65 de 9e 76 42 f1 9e 76 e3 10 a3 76 cc 8d a0 76 b2 de 9e 76 d7 96 9e 76 1f 91 9f 76 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=20
 
}