
rule Backdoor_Linux_Gafgyt_BR_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 8b 44 24 14 29 d8 ba 0a 00 00 00 89 04 24 89 d1 89 f8 31 d2 f7 f1 89 c7 8b 04 24 83 c2 30 83 fb 08 88 10 } //1
		$a_03_1 = {83 c8 ff 83 7d dc ff 0f 84 ?? ?? ?? ?? 8b 75 0c 8b 45 dc 01 c8 01 f7 89 cb c7 45 ec ff ff ff ff c7 45 f0 ff ff ff ff 89 45 e4 89 7d e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}