
rule VirTool_Win32_Obfuscator_OU{
	meta:
		description = "VirTool:Win32/Obfuscator.OU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 01 6a 02 6a 03 6a 04 6a 05 6a 06 6a 07 6a 08 ff d0 8d 35 ?? ?? ?? ?? 25 ff 00 00 00 2b f0 ff e6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}