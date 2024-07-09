
rule VirTool_Win32_Obfuscator_APJ{
	meta:
		description = "VirTool:Win32/Obfuscator.APJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 00 00 00 00 31 13 81 3b c3 (c3 c3 c3|90 90 90 90 90 90) 74 ?? 83 f8 00 75 ?? 31 13 29 c3 [0-01] 31 c0 [0-01] 31 c9 ff 05 ?? ?? ?? ?? eb } //1
		$a_03_1 = {31 13 ff 33 [0-03] 8f 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? [0-01] 31 13 83 eb 08 3d ac 04 00 00 73 08 83 c0 04 83 c3 04 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}