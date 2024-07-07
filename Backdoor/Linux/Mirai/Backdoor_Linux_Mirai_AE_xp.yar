
rule Backdoor_Linux_Mirai_AE_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 52 4f 54 5f 45 58 45 43 } //1 PROT_EXEC
		$a_00_1 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 37 } //1 /proc/self/exe7
		$a_00_2 = {2f 70 72 6f 63 2f 73 65 6d 6e } //1 /proc/semn
		$a_00_3 = {61 6e 74 69 68 6f 6e 65 79 } //1 antihoney
		$a_00_4 = {63 68 6d 6f 6e 37 } //1 chmon7
		$a_00_5 = {6d 64 65 62 75 6e 67 2e 48 69 33 32 } //1 mdebung.Hi32
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}