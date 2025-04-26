
rule Backdoor_Linux_Gafgyt_AL_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AL!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 65 6b 6b 65 72 74 65 6c 6e 65 74 } //1 hekkertelnet
		$a_01_1 = {53 47 53 47 57 55 44 32 } //1 SGSGWUD2
		$a_01_2 = {4b 47 53 56 59 47 58 41 } //1 KGSVYGXA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}