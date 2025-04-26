
rule VirTool_Win32_Obfuscator_CQ{
	meta:
		description = "VirTool:Win32/Obfuscator.CQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 cd 2d c3 64 8f 05 00 00 00 00 83 c4 04 ff 64 24 20 90 09 08 00 80 37 ?? 68 [0-50] 85 ?? 74 07 80 ?? 00 ?? ?? eb f5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}