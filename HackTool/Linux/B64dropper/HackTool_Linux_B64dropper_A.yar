
rule HackTool_Linux_B64dropper_A{
	meta:
		description = "HackTool:Linux/B64dropper.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {65 00 63 00 68 00 6f 00 90 27 ff 00 90 23 ff 0e 61 2d 7a 41 2d 5a 30 2d 39 2b 2f 3d 22 27 90 27 ff 00 7c 00 90 27 ff 00 62 00 61 00 73 00 65 00 36 00 34 00 90 27 ff 00 2d 00 64 00 90 27 ff 00 7c 00 90 27 ff 00 90 2b 02 00 73 00 68 00 90 00 } //1
		$a_02_1 = {65 00 63 00 68 00 6f 00 90 27 ff 00 90 23 ff 0e 61 2d 7a 41 2d 5a 30 2d 39 2b 2f 3d 22 27 90 27 ff 00 7c 00 90 27 ff 00 62 00 61 00 73 00 65 00 36 00 34 00 90 27 ff 00 2d 00 2d 00 64 00 65 00 63 00 6f 00 64 00 65 00 90 27 ff 00 7c 00 90 27 ff 00 90 2b 02 00 73 00 68 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}