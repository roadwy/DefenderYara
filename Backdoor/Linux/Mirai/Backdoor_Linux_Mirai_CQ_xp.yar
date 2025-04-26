
rule Backdoor_Linux_Mirai_CQ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CQ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 27 39 d8 90 03 20 f8 09 00 } //1
		$a_00_1 = {82 04 34 13 ff ff 14 40 00 37 26 32 00 14 8f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}