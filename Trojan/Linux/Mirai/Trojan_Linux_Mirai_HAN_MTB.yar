
rule Trojan_Linux_Mirai_HAN_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAN!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 68 68 75 2e 25 68 68 75 2e 25 68 68 75 2e 25 68 68 75 } //1 %hhu.%hhu.%hhu.%hhu
		$a_01_1 = {00 65 78 70 6c 6f 69 74 00 } //10
		$a_01_2 = {72 72 72 72 72 72 73 73 2f 62 69 6e 2f 73 68 } //20 rrrrrrss/bin/sh
		$a_01_3 = {2e 6d 6f 6f 6f 2e 63 6f 6d 00 00 00 08 08 08 08 08 08 04 04 01 01 01 01 01 00 00 01 d0 43 de de d0 43 dc dc 72 72 72 72 72 72 73 73 2e } //20
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20) >=31
 
}