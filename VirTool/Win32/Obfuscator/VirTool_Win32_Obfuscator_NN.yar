
rule VirTool_Win32_Obfuscator_NN{
	meta:
		description = "VirTool:Win32/Obfuscator.NN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 ec 18 c6 45 ec 47 c6 45 ed 65 c6 45 ee 74 c6 45 ef 4d } //1
		$a_01_1 = {83 ec 10 c6 45 f4 56 c6 45 f5 69 c6 45 f6 03 } //1
		$a_01_2 = {83 ec 14 c6 45 ec 03 c6 45 ed 69 c6 45 ee 03 c6 45 ef 74 } //1
		$a_01_3 = {43 72 65 61 74 65 48 61 72 64 4c 69 6e 6b 41 } //1 CreateHardLinkA
		$a_01_4 = {62 65 61 75 74 69 66 75 6c 20 66 6c 6f 77 65 72 73 20 68 65 72 65 } //1 beautiful flowers here
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}