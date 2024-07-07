
rule HackTool_Linux_Portscan_C_xp{
	meta:
		description = "HackTool:Linux/Portscan.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 61 6e 20 69 6e 20 50 72 6f 67 72 65 73 73 20 00 } //1
		$a_00_1 = {e8 00 00 00 86 f7 ff ff 08 01 00 00 fd f8 } //1
		$a_00_2 = {64 00 5f 73 74 61 72 74 00 68 6f 73 74 } //1
		$a_00_3 = {c7 45 b0 10 00 00 00 48 8d 4d b0 48 8d 55 e0 48 8b 75 c0 8b 45 b4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}