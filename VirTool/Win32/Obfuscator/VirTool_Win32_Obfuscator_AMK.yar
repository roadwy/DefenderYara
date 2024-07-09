
rule VirTool_Win32_Obfuscator_AMK{
	meta:
		description = "VirTool:Win32/Obfuscator.AMK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 8b 0f ad 4e 4e 4e 33 c1 4a 59 75 04 5a 2b f2 52 aa 49 75 eb } //1
		$a_03_1 = {55 8b ec b8 ?? ?? ?? ?? 6a 0f 03 c1 50 59 58 8f 05 ?? ?? ?? ?? 51 8b c8 41 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}