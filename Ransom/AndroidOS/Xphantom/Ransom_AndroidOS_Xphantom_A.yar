
rule Ransom_AndroidOS_Xphantom_A{
	meta:
		description = "Ransom:AndroidOS/Xphantom.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 58 50 68 61 6e 74 6f 6d 2f 69 64 2f 4d 79 53 65 72 76 69 63 65 3b } //2 Lcom/XPhantom/id/MyService;
		$a_01_1 = {61 6c 73 68 61 72 61 62 79 } //2 alsharaby
		$a_01_2 = {73 65 6e 64 42 72 65 61 6b 70 6f 69 6e 74 48 69 74 } //2 sendBreakpointHit
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}