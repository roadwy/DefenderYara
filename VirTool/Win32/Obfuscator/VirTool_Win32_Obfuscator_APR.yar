
rule VirTool_Win32_Obfuscator_APR{
	meta:
		description = "VirTool:Win32/Obfuscator.APR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff d0 83 c4 0b 44 89 c6 } //1
		$a_01_1 = {68 64 6c 6c 00 } //1
		$a_01_2 = {68 74 33 32 2e } //1 ht32.
		$a_03_3 = {6a 40 68 00 30 00 00 56 57 ff 15 ?? ?? ?? ?? 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}