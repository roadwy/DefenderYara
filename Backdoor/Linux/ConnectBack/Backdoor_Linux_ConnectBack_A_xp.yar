
rule Backdoor_Linux_ConnectBack_A_xp{
	meta:
		description = "Backdoor:Linux/ConnectBack.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 } //1
		$a_02_1 = {48 b9 02 00 ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 25 49 ff c9 74 18 57 6a 23 58 6a 00 6a 05 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 c7 6a 3c 58 6a 01 5f 0f 05 5e 6a 7e 5a 0f 05 48 85 c0 78 ed ff e6 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}