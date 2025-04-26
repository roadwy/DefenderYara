
rule VirTool_Win32_Obfuscator_ABC{
	meta:
		description = "VirTool:Win32/Obfuscator.ABC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 0e 6a 0a 6a 40 ff 15 ?? ?? ?? ?? 33 c0 c9 c3 53 56 68 28 14 00 00 6a 40 } //1
		$a_03_1 = {3b de 74 23 8d 45 fc 50 6a 40 ff 75 10 57 ff 15 ?? ?? ?? ?? 85 c0 74 0f ff 75 08 03 df ff d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}