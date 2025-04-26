
rule Backdoor_Linux_Mirai_FC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.FC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {92 42 00 04 8e 43 00 00 26 52 00 05 a0 a2 00 14 ac a3 00 04 ac a3 00 10 a4 a6 00 00 16 ?? ?? ?? 24 a5 00 18 02 d7 10 21 02 22 10 23 24 54 ff fa } //1
		$a_03_1 = {00 80 28 21 02 a4 10 21 80 43 00 20 00 00 00 00 10 ?? ?? ?? 24 02 00 20 10 ?? ?? ?? 24 82 00 01 02 42 10 21 10 ?? ?? ?? 24 06 00 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}