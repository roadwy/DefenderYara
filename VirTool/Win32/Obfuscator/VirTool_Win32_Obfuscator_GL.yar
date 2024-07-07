
rule VirTool_Win32_Obfuscator_GL{
	meta:
		description = "VirTool:Win32/Obfuscator.GL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 00 bb 04 00 00 00 83 eb 02 ba 74 12 40 00 f7 d3 f7 db 81 fc 54 45 02 00 30 1a 83 ea 03 90 83 c2 04 81 fa 74 2e 40 00 75 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}