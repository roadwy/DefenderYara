
rule Backdoor_Linux_GetShell_B_MTB{
	meta:
		description = "Backdoor:Linux/GetShell.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 7f 00 00 01 68 02 00 15 b3 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 ?? 4e 74 ?? 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 } //1
		$a_03_1 = {cd 80 93 59 b0 3f cd 80 49 79 ?? 68 c0 a8 01 4e 68 02 00 10 e1 89 e1 b0 66 50 51 53 b3 03 89 e1 cd 80 52 ba 00 00 73 68 66 ba 6e 2f 52 ba 00 00 62 69 66 ba 2f 2f 52 31 d2 89 e3 52 53 89 e1 b0 0b cd 80 } //1
		$a_00_2 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 2e 69 79 44 68 02 00 da c2 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd } //1
		$a_00_3 = {6a 0a 5e 31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 a4 5c dd 9e 68 02 00 11 5c 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 85 c0 78 10 5b 89 e1 99 b2 6a b0 03 cd 80 85 c0 78 02 ff e1 b8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}