
rule VirTool_Win32_Obfuscator_AIC{
	meta:
		description = "VirTool:Win32/Obfuscator.AIC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 6b 66 6e 6b 77 65 64 6c 73 00 } //1
		$a_00_1 = {01 75 68 68 38 00 } //1 甁桨8
		$a_01_2 = {c7 45 e8 28 3a 00 00 c7 45 f0 31 62 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}