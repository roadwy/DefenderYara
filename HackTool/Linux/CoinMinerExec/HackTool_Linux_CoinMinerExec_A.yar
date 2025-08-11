
rule HackTool_Linux_CoinMinerExec_A{
	meta:
		description = "HackTool:Linux/CoinMinerExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 64 00 20 00 } //2 sed 
		$a_00_1 = {2e 00 62 00 61 00 73 00 68 00 67 00 6f 00 } //2 .bashgo
		$a_00_2 = {7c 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 } //2 |pastebin
		$a_00_3 = {7c 00 6f 00 6e 00 69 00 6f 00 6e 00 } //2 |onion
		$a_00_4 = {7c 00 62 00 70 00 72 00 6f 00 66 00 72 00 } //2 |bprofr
		$a_00_5 = {7c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 } //2 |python
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=12
 
}