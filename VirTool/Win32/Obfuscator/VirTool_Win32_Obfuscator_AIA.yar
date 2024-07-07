
rule VirTool_Win32_Obfuscator_AIA{
	meta:
		description = "VirTool:Win32/Obfuscator.AIA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db 8d bb 00 41 7a 00 b9 00 04 00 00 83 f9 00 74 0a 8a 07 34 55 49 88 07 47 75 f1 61 5e 87 fe ff d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}