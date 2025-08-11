
rule HackTool_MacOS_SuspScreenCapture_A1{
	meta:
		description = "HackTool:MacOS/SuspScreenCapture.A1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 72 00 65 00 65 00 6e 00 63 00 61 00 70 00 74 00 75 00 72 00 65 00 20 00 2d 00 78 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //10 screencapture -x /tmp/
	condition:
		((#a_00_0  & 1)*10) >=10
 
}