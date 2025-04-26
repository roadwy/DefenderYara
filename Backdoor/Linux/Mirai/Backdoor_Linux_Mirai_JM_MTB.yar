
rule Backdoor_Linux_Mirai_JM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 13 41 83 ed 05 89 51 10 0f b6 43 04 48 83 c3 05 66 c7 01 02 00 89 51 04 88 41 14 48 83 c1 18 48 39 f3 } //1
		$a_01_1 = {4c 63 db 31 d2 45 31 d2 49 f7 f3 bd ff ff ff ff 41 89 d4 48 89 c6 31 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}