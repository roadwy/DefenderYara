
rule VirTool_Win32_Obfuscator_AJU{
	meta:
		description = "VirTool:Win32/Obfuscator.AJU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 8d 7c 3d ?? 8a 17 80 f2 ?? 80 ea ?? 88 17 8b 55 ?? 8b 7d ?? 80 f2 ?? 80 ea ?? 02 c2 3c 08 72 dd } //1
	condition:
		((#a_03_0  & 1)*1) >=10
 
}