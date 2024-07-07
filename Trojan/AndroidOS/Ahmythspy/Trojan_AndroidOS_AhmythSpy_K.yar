
rule Trojan_AndroidOS_AhmythSpy_K{
	meta:
		description = "Trojan:AndroidOS/AhmythSpy.K,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 50 65 72 6d 47 65 72 61 69 73 } //2 ServicePermGerais
		$a_01_1 = {78 30 30 30 30 6e 6f 74 69 66 } //2 x0000notif
		$a_01_2 = {63 6f 64 69 67 6f 73 62 6e 6b 73 6f 6b } //2 codigosbnksok
		$a_01_3 = {78 30 30 30 30 73 63 72 6e 6c 6b } //2 x0000scrnlk
		$a_01_4 = {41 63 74 69 76 69 74 79 42 4e 4b } //2 ActivityBNK
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}