
rule VirTool_Win32_Obfuscator_ZW{
	meta:
		description = "VirTool:Win32/Obfuscator.ZW,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 5c 74 65 73 74 31 32 33 5c [30-39] [30-39] [30-39] [30-39] 5c 52 65 6c 65 6[30-39] [3] [30-39] [3] [30-39] [3] [30-39] [3] 0-39] [30-39] [30-39] 2e 70 64 62 90 09 0a 00 (64|65) 3a 5c 44 6f 77 6e 6c 6f 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}