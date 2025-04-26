
rule Backdoor_Linux_Mirai_HZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 54 31 c0 be 00 08 01 00 55 53 31 db 48 81 ec ?? 00 00 00 e8 57 fd ff ff 85 c0 89 c5 0f 88 ?? ?? ?? ?? 48 89 e6 89 c7 e8 8b 29 00 00 85 c0 78 ?? 31 c0 ba 01 00 00 00 be 02 00 00 00 89 ef } //1
		$a_03_1 = {c7 00 00 00 00 00 be 02 00 00 00 bf 02 00 00 00 e8 86 11 00 00 89 c5 31 c0 83 fd ff 74 ?? ba 10 00 00 00 48 89 e6 89 ef 66 c7 04 24 02 00 c7 44 24 04 08 08 08 08 66 c7 44 24 02 00 35 e8 f1 0f 00 00 ?? ?? ?? ?? ?? 48 89 e6 89 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}