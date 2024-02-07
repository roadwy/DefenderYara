
rule HackTool_Linux_CopyBashtoTemp_A{
	meta:
		description = "HackTool:Linux/CopyBashtoTemp.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 00 70 00 20 00 2d 00 69 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //0a 00  cp -i /bin/bash /tmp/
		$a_01_1 = {63 00 70 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 62 00 61 00 73 00 68 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //0a 00  cp /bin/bash /tmp/
		$a_01_2 = {63 00 70 00 20 00 2d 00 69 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //0a 00  cp -i /bin/sh /tmp/
		$a_01_3 = {63 00 70 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //00 00  cp /bin/sh /tmp/
	condition:
		any of ($a_*)
 
}