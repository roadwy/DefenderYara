
rule VirTool_Win32_Obfuscator_HJ{
	meta:
		description = "VirTool:Win32/Obfuscator.HJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d5 89 ee 81 f3 14 00 00 00 89 ee f7 d5 4d 75 ef 81 f3 13 00 00 00 81 f3 1e 00 00 00 33 1f ?? 89 dd 89 ed 89 2f 83 c7 02 47 47 ?? 81 c2 02 00 00 00 4a ?? 49 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}