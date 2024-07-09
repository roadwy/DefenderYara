
rule VirTool_WinNT_Citeary_B{
	meta:
		description = "VirTool:WinNT/Citeary.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {63 3a 5c 75 73 65 72 73 5c 69 63 79 68 65 61 72 74 5c 64 6f 63 75 6d 65 7e 31 5c 76 69 73 75 61 6c 7e ?? 5c 70 72 6f 6a 65 63 74 73 5c 64 6f 77 6e 6c 6f 61 64 5c } //1
		$a_00_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_2 = {54 00 68 00 65 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 20 00 66 00 6f 00 72 00 20 00 74 00 68 00 65 00 20 00 73 00 75 00 70 00 65 00 72 00 63 00 6f 00 6f 00 6c 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 2d 00 62 00 61 00 73 00 65 00 64 00 20 00 74 00 6f 00 6f 00 6c 00 } //1 The driver for the supercool driver-based tool
		$a_02_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 [0-ff] 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}