
rule Trojan_Linux_AntiForensicsCmdHistory_B{
	meta:
		description = "Trojan:Linux/AntiForensicsCmdHistory.B,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {6c 00 6e 00 20 00 } //10 ln 
		$a_00_1 = {2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 } //10 /dev/null
		$a_00_2 = {2f 00 2e 00 62 00 61 00 73 00 68 00 5f 00 68 00 69 00 73 00 74 00 6f 00 72 00 79 00 } //10 /.bash_history
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}