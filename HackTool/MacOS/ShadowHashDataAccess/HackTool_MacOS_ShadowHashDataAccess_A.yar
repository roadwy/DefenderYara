
rule HackTool_MacOS_ShadowHashDataAccess_A{
	meta:
		description = "HackTool:MacOS/ShadowHashDataAccess.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {64 00 73 00 63 00 6c 00 [0-20] 72 00 65 00 61 00 64 00 [0-50] 64 00 73 00 61 00 74 00 74 00 72 00 74 00 79 00 70 00 65 00 6e 00 61 00 74 00 69 00 76 00 65 00 3a 00 73 00 68 00 61 00 64 00 6f 00 77 00 68 00 61 00 73 00 68 00 64 00 61 00 74 00 61 00 } //10
		$a_00_1 = {2d 00 72 00 65 00 61 00 64 00 20 00 2f 00 55 00 73 00 65 00 72 00 73 00 2f 00 70 00 61 00 6e 00 6f 00 70 00 74 00 6f 00 5f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 } //-100 -read /Users/panopto_upload
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*-100) >=10
 
}