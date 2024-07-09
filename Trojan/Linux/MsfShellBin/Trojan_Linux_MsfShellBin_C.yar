
rule Trojan_Linux_MsfShellBin_C{
	meta:
		description = "Trojan:Linux/MsfShellBin.C,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 89 e1 6a 09 5b 6a 66 58 cd 80 83 c4 10 59 5b } //1
		$a_03_1 = {6a 7d 58 99 b2 07 b9 00 10 00 00 89 e3 66 81 e3 00 f0 cd 80 31 db f7 e3 53 43 53 6a ?? 89 e1 b0 66 cd 80 51 6a 04 54 6a 02 6a 01 50 97 89 e1 6a 0e 5b 6a 66 58 cd 80 } //1
		$a_01_2 = {51 50 89 e1 6a 66 58 cd 80 d1 e3 b0 66 cd 80 57 43 b0 66 89 51 04 cd 80 93 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}