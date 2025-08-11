
rule Trojan_BAT_Taskun_SS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 11 07 11 08 91 6f c7 00 00 0a 00 00 11 08 17 58 13 08 11 08 11 04 fe 04 13 09 11 09 2d e0 } //2
		$a_01_1 = {57 6f 72 64 46 75 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 WordFun.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Taskun_SS_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 11 4a 11 4b 91 6f e3 00 00 0a 00 17 11 42 28 db 00 00 0a 13 04 1c 8d 3c 00 00 01 25 16 72 d7 0e 00 70 a2 25 17 12 4b 28 48 00 00 0a a2 25 18 72 e9 0e 00 70 a2 25 19 12 31 28 48 00 00 0a a2 25 1a 72 e9 0e 00 70 a2 25 1b 12 35 28 48 00 00 0a a2 28 e2 00 00 0a 13 0a 00 11 4b 17 58 13 4b 11 4b 11 42 fe 04 13 4c 11 4c 2d 93 } //2
		$a_01_1 = {4f 79 75 6e 75 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Oyunu.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}