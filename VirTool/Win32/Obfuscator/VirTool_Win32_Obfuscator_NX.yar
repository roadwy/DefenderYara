
rule VirTool_Win32_Obfuscator_NX{
	meta:
		description = "VirTool:Win32/Obfuscator.NX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f8 47 75 35 8b 45 08 0f be 40 03 83 f8 4d 75 29 8b 45 08 0f be 40 09 83 f8 46 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}