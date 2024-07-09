
rule VirTool_Win32_Obfuscator_ADT{
	meta:
		description = "VirTool:Win32/Obfuscator.ADT,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 5c 38 01 b3 65 b2 4d b0 46 b1 57 } //1
		$a_03_1 = {ff d6 8b 3d ?? ?? ?? ?? 50 ff d7 a3 90 09 18 00 c6 45 ?? 43 c6 45 ?? 6f c6 45 ?? 75 c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}