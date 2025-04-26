
rule HackTool_Linux_Wingate_A_xp{
	meta:
		description = "HackTool:Linux/Wingate.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 67 61 74 65 2e 63 } //2 wgate.c
		$a_01_1 = {57 69 6e 67 61 74 65 20 66 6f 75 6e 64 3a 20 25 73 } //1 Wingate found: %s
		$a_01_2 = {57 69 6e 67 61 74 65 20 53 65 65 6b 65 72 20 62 79 20 4b 42 79 74 65 } //1 Wingate Seeker by KByte
		$a_01_3 = {4e 65 74 70 72 6f 78 79 3e } //1 Netproxy>
		$a_01_4 = {75 73 65 3a 20 25 73 20 69 6e 66 69 6c 65 20 6f 75 74 66 69 6c 65 } //1 use: %s infile outfile
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}