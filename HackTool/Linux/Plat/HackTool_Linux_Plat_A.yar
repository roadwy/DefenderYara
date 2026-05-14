
rule HackTool_Linux_Plat_A{
	meta:
		description = "HackTool:Linux/Plat.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 77 61 6e 67 79 69 68 61 6e 67 2f 70 6c 61 74 79 70 75 73 } //1 github.com/wangyihang/platypus
		$a_00_1 = {68 74 74 70 32 73 65 72 76 65 72 43 6f 6e 6e } //1 http2serverConn
		$a_00_2 = {62 6f 64 79 70 75 6c 6c 74 75 6e 6e 65 6c 63 6f 6e 6e 65 63 74 } //1 bodypulltunnelconnect
		$a_00_3 = {62 6f 64 79 70 75 73 68 74 75 6e 6e 65 6c 63 72 65 61 74 65 } //1 bodypushtunnelcreate
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}