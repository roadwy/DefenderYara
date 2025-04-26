
rule Backdoor_Linux_Mirai_K_xp{
	meta:
		description = "Backdoor:Linux/Mirai.K!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {74 63 70 66 72 61 67 20 73 74 61 72 74 65 64 00 74 63 70 61 6c 6c 20 73 74 61 72 74 65 64 00 00 2f 00 00 00 32 30 39 2e 31 34 31 2e 34 32 2e 31 34 39 00 } //1
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}