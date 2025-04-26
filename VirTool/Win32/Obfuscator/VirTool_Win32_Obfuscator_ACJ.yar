
rule VirTool_Win32_Obfuscator_ACJ{
	meta:
		description = "VirTool:Win32/Obfuscator.ACJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 55 0c 8d 44 0a ff a3 ?? ?? ?? ?? 8b 4d 0c 8b 55 fc 8d 44 0a ff a3 90 1b 00 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}