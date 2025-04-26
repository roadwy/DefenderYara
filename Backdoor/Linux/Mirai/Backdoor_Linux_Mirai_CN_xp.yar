
rule Backdoor_Linux_Mirai_CN_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CN!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {a7 8c 08 00 e0 03 21 10 e0 00 06 00 1c 3c 4c b4 9c } //1
		$a_00_1 = {18 83 99 8f 01 00 04 26 09 f8 20 03 01 00 } //1
		$a_00_2 = {00 a4 8c 00 00 00 00 fb ff 80 10 00 00 00 00 ec } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}