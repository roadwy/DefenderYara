
rule HackTool_Linux_Bangsyn_A_xp{
	meta:
		description = "HackTool:Linux/Bangsyn.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 79 6e 74 61 78 3a 20 2e 2f 62 61 6e 67 73 79 6e 20 69 70 20 70 6f 72 74 20 74 69 6d 65 } //1 syntax: ./bangsyn ip port time
		$a_01_1 = {62 61 6e 67 73 79 6e 2e 63 } //2 bangsyn.c
		$a_01_2 = {64 6f 73 79 6e 70 61 63 6b 65 74 } //1 dosynpacket
		$a_01_3 = {73 61 6e 74 6f 6e 67 20 73 79 6e } //1 santong syn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}