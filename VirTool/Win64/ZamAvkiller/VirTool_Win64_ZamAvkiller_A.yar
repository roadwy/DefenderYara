
rule VirTool_Win64_ZamAvkiller_A{
	meta:
		description = "VirTool:Win64/ZamAvkiller.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 6c 6f 61 64 64 72 69 76 } //1 main.loaddriv
		$a_01_1 = {65 64 72 63 68 65 63 6b 2e 64 65 66 65 72 77 72 61 70 } //1 edrcheck.deferwrap
		$a_01_2 = {65 64 72 6c 69 73 74 63 68 65 63 6b } //1 edrlistcheck
		$a_01_3 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //1 DeviceIoControl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}