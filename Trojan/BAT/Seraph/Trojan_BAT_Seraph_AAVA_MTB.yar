
rule Trojan_BAT_Seraph_AAVA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 7b 19 00 00 0a 02 7b 1c 00 00 0a 03 02 7b 1c 00 00 0a 91 02 7b 1b 00 00 0a 61 d2 9c } //2
		$a_01_1 = {02 02 7b 17 00 00 0a 02 7b 16 00 00 0a 02 7b 1c 00 00 0a 94 58 02 7b 1d 00 00 0a 02 7b 1c 00 00 0a 94 58 20 00 01 00 00 5d } //2
		$a_01_2 = {57 00 67 00 6c 00 77 00 77 00 6b 00 62 00 6c 00 76 00 69 00 } //2 Wglwwkblvi
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}