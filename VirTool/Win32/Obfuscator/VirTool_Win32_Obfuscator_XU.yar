
rule VirTool_Win32_Obfuscator_XU{
	meta:
		description = "VirTool:Win32/Obfuscator.XU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 c6 01 00 00 00 56 81 c6 01 00 00 00 81 c6 01 00 00 00 e9 ?? ?? 00 00 81 c7 01 00 00 00 81 c0 01 00 00 00 81 c3 01 00 00 00 03 d8 81 c0 01 00 00 00 81 c3 01 00 00 00 03 c3 81 c3 01 00 00 00 81 c0 01 00 00 00 e9 ?? ?? ff ff } //1
		$a_03_1 = {d1 e0 50 81 c3 ?? ?? 00 00 05 ?? ?? 00 00 05 ?? ?? 00 00 81 c3 ?? ?? 00 00 81 c1 ?? ?? 00 00 e9 ?? ?? ff ff 81 e9 01 00 00 00 03 c1 81 c0 01 00 00 00 03 c3 81 c0 01 00 00 00 5f 81 c1 01 00 00 00 81 e9 01 00 00 00 83 c1 0c 81 eb 01 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}