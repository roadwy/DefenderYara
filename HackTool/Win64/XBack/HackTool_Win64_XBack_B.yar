
rule HackTool_Win64_XBack_B{
	meta:
		description = "HackTool:Win64/XBack.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 32 37 2e 30 2e 30 2e 31 00 00 00 63 6d 64 00 70 6f 77 65 72 73 68 65 6c 6c 00 00 3d 00 00 00 2d 2d ?? ?? ?? ?? ?? ?? 62 6f 74 5f 73 65 72 76 65 72 20 3c 73 65 72 76 65 72 3a 70 6f 72 74 3e 20 3c 75 75 69 64 3e 2e 20 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}