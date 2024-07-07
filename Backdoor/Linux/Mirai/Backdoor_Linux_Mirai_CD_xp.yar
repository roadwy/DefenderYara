
rule Backdoor_Linux_Mirai_CD_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 57 e3 04 30 c0 e5 01 30 84 e2 2d 00 00 0a 01 40 d3 e5 09 } //1
		$a_00_1 = {00 52 e1 0c 00 00 0a 02 c1 91 e7 10 e0 9d e5 04 30 dc e5 0e 00 53 e1 f7 ff ff 1a 00 60 8d e5 14 00 9d e5 09 10 a0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}