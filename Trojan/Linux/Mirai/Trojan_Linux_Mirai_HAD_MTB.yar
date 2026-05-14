
rule Trojan_Linux_Mirai_HAD_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,3c 00 3c 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 61 6c 63 30 6e 74 72 30 6c } //30 talc0ntr0l
		$a_01_1 = {42 4f 54 5f 49 44 5f 4e 4f 54 5f } //10 BOT_ID_NOT_
		$a_01_2 = {62 79 74 65 73 20 66 72 6f 6d 20 63 6e 63 } //10 bytes from cnc
		$a_01_3 = {65 6a 65 63 74 65 64 20 62 79 20 43 4e 43 } //10 ejected by CNC
		$a_01_4 = {5b 25 73 3a 25 64 5d 20 4f 4f 4d 20 6b 69 6c 6c 65 72 } //10 [%s:%d] OOM killer
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=60
 
}