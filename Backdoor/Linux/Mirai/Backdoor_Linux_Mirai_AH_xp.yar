
rule Backdoor_Linux_Mirai_AH_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AH!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 73 75 6d 2e 68 } //1 checksum.h
		$a_01_1 = {6b 69 6c 6c 65 72 2e 68 } //1 killer.h
		$a_01_2 = {6b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 65 73 } //1 killing processes
		$a_01_3 = {61 74 74 61 63 6b 2e 68 } //1 attack.h
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}