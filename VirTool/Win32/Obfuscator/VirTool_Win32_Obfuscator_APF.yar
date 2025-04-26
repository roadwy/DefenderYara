
rule VirTool_Win32_Obfuscator_APF{
	meta:
		description = "VirTool:Win32/Obfuscator.APF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 6a 08 58 69 c0 ?? ?? 00 00 8b 4d ?? dd 05 ?? ?? 40 00 dd 1c 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}