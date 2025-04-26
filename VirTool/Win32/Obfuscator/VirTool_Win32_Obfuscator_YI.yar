
rule VirTool_Win32_Obfuscator_YI{
	meta:
		description = "VirTool:Win32/Obfuscator.YI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 64 73 6c 64 70 63 2e 64 6c 6c } //1 adsldpc.dll
		$a_02_1 = {29 ce 47 8a 57 ff 32 c9 3a 15 ?? ?? ?? ?? 75 c3 } //1
		$a_02_2 = {8a 57 01 32 1d ?? ?? ?? ?? 3a 15 ?? ?? ?? ?? 75 b2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}