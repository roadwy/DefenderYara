
rule VirTool_Win32_Obfuscator_YI{
	meta:
		description = "VirTool:Win32/Obfuscator.YI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 64 73 6c 64 70 63 2e 64 6c 6c } //01 00  adsldpc.dll
		$a_02_1 = {29 ce 47 8a 57 ff 32 c9 3a 15 90 01 04 75 c3 90 00 } //01 00 
		$a_02_2 = {8a 57 01 32 1d 90 01 04 3a 15 90 01 04 75 b2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}