
rule VirTool_Win32_Obfuscator_GC{
	meta:
		description = "VirTool:Win32/Obfuscator.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e9 0c ff ff ff 90 01 04 55 8b ec 53 56 57 8b 75 08 8b 7d 0c 8b 5d 10 33 d2 03 df a4 3b fb 73 4a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}