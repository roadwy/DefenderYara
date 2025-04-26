
rule Backdoor_Linux_Mirai_BD_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BD!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 72 65 61 6d 62 6f 78 } //2 dreambox
		$a_01_1 = {78 6d 68 64 69 70 63 } //2 xmhdipc
		$a_01_2 = {49 73 24 75 70 65 72 40 64 6d 69 6e } //1 Is$uper@dmin
		$a_01_3 = {6d 65 69 6e 73 6d } //1 meinsm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}