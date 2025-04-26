
rule Backdoor_Linux_Mirai_JR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {82 1b 00 01 84 00 40 0a 82 38 40 02 80 88 40 0b 02 ?? ?? ?? [0-20] 04 c2 0a 3f fc 84 0a 60 ff 86 02 3f fd 80 a0 40 02 9a 02 3f fe 12 ?? ?? ?? 82 02 3f fc } //1
		$a_03_1 = {c2 4a 00 00 c2 0a 00 00 82 00 40 01 c4 50 c0 01 c2 0a 40 00 82 00 40 01 c2 50 c0 01 84 a0 80 01 12 ?? ?? ?? 01 00 00 00 c2 4a 00 00 80 a0 60 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}