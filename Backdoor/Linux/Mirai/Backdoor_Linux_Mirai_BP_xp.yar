
rule Backdoor_Linux_Mirai_BP_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BP!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5 } //1
		$a_00_1 = {5e 2e 8d e2 17 1d 8d e2 10 30 a0 e3 04 20 82 e2 08 10 81 e2 e4 35 8d e5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}