
rule Backdoor_Linux_Sshdkit_C_xp{
	meta:
		description = "Backdoor:Linux/Sshdkit.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3b 3a 74 10 ff c1 48 83 c2 04 81 f9 80 00 00 00 75 ee 30 c9 } //1
		$a_00_1 = {66 83 3f 0a 48 89 fa 75 3b 83 7f 08 00 75 35 83 7f 0c 00 75 2f 81 7f 10 00 00 ff ff 75 26 44 8b 4f 14 66 44 8b 47 02 b9 04 00 00 00 31 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}