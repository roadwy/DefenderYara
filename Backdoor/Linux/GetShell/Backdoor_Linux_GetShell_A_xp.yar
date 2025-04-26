
rule Backdoor_Linux_GetShell_A_xp{
	meta:
		description = "Backdoor:Linux/GetShell.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 97 48 b9 02 00 ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 6a 03 5e 48 ff ce 6a 21 58 0f 05 75 f6 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 52 57 48 89 e6 0f 05 } //1
		$a_02_1 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 b2 07 b9 00 10 00 00 89 e3 c1 eb 0c c1 e3 0c b0 7d cd 80 5b 89 e1 99 b6 0c b0 03 cd 80 ff e1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}