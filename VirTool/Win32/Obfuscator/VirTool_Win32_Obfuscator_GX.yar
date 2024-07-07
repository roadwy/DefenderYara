
rule VirTool_Win32_Obfuscator_GX{
	meta:
		description = "VirTool:Win32/Obfuscator.GX,SIGNATURE_TYPE_PEHSTR,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 60 9c bb 34 27 00 00 50 89 f8 31 ff 5b 9d 61 9c 60 9c bb 34 27 00 00 50 89 f8 31 ff 5b 9d 61 bb 34 27 00 00 60 9c bb 34 27 00 00 50 89 f8 31 ff 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}