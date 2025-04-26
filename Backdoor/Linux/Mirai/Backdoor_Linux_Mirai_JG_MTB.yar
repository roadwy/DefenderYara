
rule Backdoor_Linux_Mirai_JG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 29 03 02 c7 b9 cf bb 65 79 40 29 05 04 88 70 05 25 45 00 02 7a 59 60 25 ?? ?? ?? 59 60 b6 ?? e0 7f 00 d8 ff 14 83 80 } //1
		$a_03_1 = {fc 10 01 80 42 20 03 01 07 21 41 01 00 21 84 0f fe 7e ff fe 07 21 01 01 06 26 41 70 01 81 00 01 16 ?? 23 8b 0b ?? ?? ?? e0 7f 42 20 40 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}