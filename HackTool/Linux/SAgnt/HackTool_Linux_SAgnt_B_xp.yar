
rule HackTool_Linux_SAgnt_B_xp{
	meta:
		description = "HackTool:Linux/SAgnt.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 4d 45 53 53 41 47 45 53 } //1 modMESSAGES
		$a_01_1 = {74 68 65 20 70 72 6f 63 65 73 73 20 74 69 6d 65 20 69 73 20 25 64 20 6d 73 } //1 the process time is %d ms
		$a_01_2 = {6d 6f 64 53 45 43 55 52 45 } //1 modSECURE
		$a_01_3 = {6d 6f 64 53 59 53 4c 4f 47 } //1 modSYSLOG
		$a_01_4 = {63 6c 65 61 6e 69 6e 67 20 6c 6f 67 73 20 66 69 6c 65 20 66 69 6e 69 73 68 65 64 } //1 cleaning logs file finished
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}