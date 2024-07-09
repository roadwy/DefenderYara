
rule Trojan_Linux_MsfShellBin_B{
	meta:
		description = "Trojan:Linux/MsfShellBin.B,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 6e 2f 73 68 68 2f 2f 62 69 89 e3 52 53 89 e1 b0 0b cd 80 } //1
		$a_01_1 = {68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80 } //1
		$a_03_2 = {6a 66 58 cd 80 d1 e3 b0 66 cd 80 57 43 b0 66 89 51 ?? cd 80 93 b6 0c b0 03 cd 80 87 df 5b b0 06 cd 80 ff e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}