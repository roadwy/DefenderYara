
rule HackTool_Linux_SuspNodeActivity_B{
	meta:
		description = "HackTool:Linux/SuspNodeActivity.B,SIGNATURE_TYPE_CMDHSTR_EXT,3d 00 3d 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 00 62 00 69 00 6e 00 2f 00 73 00 68 00 20 00 2d 00 63 00 } //20 /bin/sh -c
		$a_00_1 = {65 00 63 00 68 00 6f 00 20 00 } //20 echo 
		$a_00_2 = {62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 64 00 } //20 base64 -d
		$a_00_3 = {7c 00 20 00 73 00 68 00 } //1 | sh
		$a_00_4 = {7c 00 73 00 68 00 } //1 |sh
		$a_00_5 = {7c 00 20 00 62 00 61 00 73 00 68 00 } //1 | bash
		$a_00_6 = {7c 00 62 00 61 00 73 00 68 00 } //1 |bash
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*20+(#a_00_2  & 1)*20+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=61
 
}