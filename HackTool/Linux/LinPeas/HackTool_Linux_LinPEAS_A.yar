
rule HackTool_Linux_LinPEAS_A{
	meta:
		description = "HackTool:Linux/LinPEAS.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_00_1 = {77 00 67 00 65 00 74 00 } //1 wget
		$a_00_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 69 00 6e 00 70 00 65 00 61 00 73 00 2e 00 73 00 68 00 } //10 http://linpeas.sh
		$a_00_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6c 00 69 00 6e 00 70 00 65 00 61 00 73 00 2e 00 73 00 68 00 } //10 https://linpeas.sh
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=11
 
}