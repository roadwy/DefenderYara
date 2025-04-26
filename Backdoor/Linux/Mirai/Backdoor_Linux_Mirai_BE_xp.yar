
rule Backdoor_Linux_Mirai_BE_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //1 /bin/busybox
		$a_01_1 = {44 4f 53 20 42 4f 54 20 4b 49 4c 4c 49 4e 47 } //1 DOS BOT KILLING
		$a_01_2 = {64 72 6f 70 62 65 61 72 } //1 dropbear
		$a_01_3 = {76 61 72 2f 74 6d 70 2f 73 6f 6e 69 61 } //1 var/tmp/sonia
		$a_01_4 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 } //1 Self Rep Fucking NeTiS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}