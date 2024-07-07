
rule Backdoor_Linux_Mirai_AY_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AY!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {89 f1 29 d9 0f 84 0a ff ff ff 31 c0 8b 5c 24 1c 8a 44 24 2b 8b 74 24 24 83 f9 01 8d 1c de 8d 14 38 89 5c 24 34 8b 5c 24 1c 8a 02 88 44 de 04 0f 84 df fe ff ff 8a 42 01 31 db 8d 71 fe 88 c3 88 44 24 2b 39 de 0f 8c c9 fe ff ff 8d 7a 02 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}