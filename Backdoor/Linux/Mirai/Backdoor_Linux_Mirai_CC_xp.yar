
rule Backdoor_Linux_Mirai_CC_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CC!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {08 a0 e1 20 08 a0 e1 70 80 bd e8 f0 4f 2d e9 22 dc 4d e2 24 d0 4d e2 01 aa 8d e2 24 a0 8a e2 21 a0 4a e2 24 b0 } //1
		$a_00_1 = {e5 00 00 52 e3 3a 00 52 13 00 30 a0 03 01 30 a0 13 03 10 a0 01 05 00 00 0a 00 10 a0 e3 01 10 81 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}