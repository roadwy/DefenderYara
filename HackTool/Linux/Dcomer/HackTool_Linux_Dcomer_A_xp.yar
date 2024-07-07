
rule HackTool_Linux_Dcomer_A_xp{
	meta:
		description = "HackTool:Linux/Dcomer.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 25 73 20 3c 61 2d 62 6c 6f 63 6b 3e 20 3c 70 6f 72 74 3e 20 5b 62 2d 62 6c 6f 63 6b 5d 20 5b 63 2d 62 6c 6f 63 6b 5d } //1 Usage: %s <a-block> <port> [b-block] [c-block]
		$a_01_1 = {62 64 65 20 45 78 70 20 24 } //1 bde Exp $
		$a_01_2 = {6f 62 72 69 65 6e 20 45 78 70 20 24 } //1 obrien Exp $
		$a_01_3 = {41 74 74 65 6d 70 74 69 6e 67 20 52 50 43 2f 44 43 4f 4d 20 6f 6e } //1 Attempting RPC/DCOM on
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}