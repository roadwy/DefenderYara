
rule VirTool_Win32_Obfuscator_YC{
	meta:
		description = "VirTool:Win32/Obfuscator.YC,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 54 0c 04 c1 e1 04 03 c8 89 0a 83 c4 14 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}