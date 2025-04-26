
rule VirTool_WinNT_Mader_B{
	meta:
		description = "VirTool:WinNT/Mader.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 72 69 76 65 72 3a 20 53 74 61 72 74 65 64 20 5b } //1 Driver: Started [
		$a_00_1 = {5c 00 77 00 69 00 6e 00 6e 00 74 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 \winnt\explorer.exe
		$a_00_2 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 } //1
		$a_01_3 = {43 6f 72 65 20 28 25 78 29 0a 00 55 8b ec 83 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}