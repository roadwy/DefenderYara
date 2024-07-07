
rule Backdoor_Linux_Getshell_E_MTB{
	meta:
		description = "Backdoor:Linux/Getshell.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {14 59 5b 5e 52 68 02 00 11 5c 6a 10 51 50 89 e1 6a 66 58 cd 80 d1 e3 b0 66 cd 80 57 43 b0 66 89 51 04 cd 80 93 89 df 53 51 6a 00 6a 10 e8 10 00 00 } //1
		$a_01_1 = {10 00 00 31 db 53 89 e6 6a 40 b7 0a 53 56 53 89 e1 86 fb 66 ff 01 6a 66 58 cd 80 81 3e } //1
		$a_01_2 = {85 c0 79 44 4e 74 68 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 52 53 51 6a 00 6a 10 e8 10 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}