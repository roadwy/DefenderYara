
rule VirTool_Win32_Obfuscator_SZ{
	meta:
		description = "VirTool:Win32/Obfuscator.SZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 45 f8 50 6a 40 ff 77 50 ff 75 fc ff 15 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 68 00 00 10 00 6a 00 ff 15 90 01 04 8b f0 8d 45 fc 50 ff 75 14 8d 45 f8 ff 75 08 c6 06 03 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}