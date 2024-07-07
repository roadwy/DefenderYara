
rule VirTool_Win32_Obfuscator_WP{
	meta:
		description = "VirTool:Win32/Obfuscator.WP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 d2 03 35 90 01 04 29 ce 47 8a 57 ff 32 c9 3a 15 90 01 04 75 c8 8a 57 01 32 1d 90 01 04 3a 15 90 01 04 75 b7 c6 05 90 01 03 00 20 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}