
rule VirTool_Win32_Obfuscator_ADG{
	meta:
		description = "VirTool:Win32/Obfuscator.ADG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c2 75 f6 33 c0 b1 90 01 01 2a ca 28 88 90 01 04 40 3d 90 01 04 75 ee 8d 05 90 00 } //1
		$a_03_1 = {ff 77 50 ff 77 34 ff 75 90 01 01 ff d0 89 45 90 01 01 8d 85 90 01 04 c7 00 57 72 69 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}