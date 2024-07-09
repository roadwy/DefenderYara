
rule VirTool_Win32_Obfuscator_ARJ_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ARJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 ?? ec 8b 4d ?? 3b 4d ?? 73 ?? 8b 55 ?? 03 55 ?? 33 c0 8a 02 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}