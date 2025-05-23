
rule HackTool_Linux_LinTools_A{
	meta:
		description = "HackTool:Linux/LinTools.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_00_0 = {67 00 69 00 74 00 20 00 63 00 6c 00 6f 00 6e 00 65 00 } //1 git clone
		$a_00_1 = {77 00 67 00 65 00 74 00 } //1 wget
		$a_00_2 = {63 00 75 00 72 00 6c 00 } //1 curl
		$a_02_3 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 90 23 ff 0e 61 2d 7a 41 2d 5a 30 2d 39 5f 7e 2e 2f 2d 50 00 45 00 41 00 53 00 53 00 2d 00 6e 00 67 00 } //10
		$a_02_4 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 90 23 ff 0e 61 2d 7a 41 2d 5a 30 2d 39 5f 7e 2e 2f 2d 4c 00 69 00 6e 00 45 00 6e 00 75 00 6d 00 } //10
		$a_02_5 = {67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 90 23 ff 0e 61 2d 7a 41 2d 5a 30 2d 39 5f 7e 2e 2f 2d 6c 00 69 00 6e 00 69 00 6b 00 61 00 74 00 7a 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10+(#a_02_4  & 1)*10+(#a_02_5  & 1)*10) >=11
 
}