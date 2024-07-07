
rule Backdoor_Linux_Gafgyt_Z_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.Z!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 51 5a 49 51 5a 4c 51 5a 4c 51 5a 41 51 5a 54 51 5a 54 51 5a 4b } //1 KQZIQZLQZLQZAQZTQZTQZK
		$a_01_1 = {4c 51 5a 4f 51 5a 4c 51 5a 4e 51 5a 4f 51 5a 47 51 5a 54 51 5a 46 51 5a 4f } //1 LQZOQZLQZNQZOQZGQZTQZFQZO
		$a_01_2 = {55 51 5a 44 51 5a 50 } //1 UQZDQZP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}