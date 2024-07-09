
rule VirTool_Win32_Obfuscator_ZAI_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAI!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d0 03 c3 8a 0c 1a 88 0c 30 60 8b 4d 08 8a 45 ff d3 e3 33 db 0b 1d ?? ?? ?? ?? 03 d9 8a 33 90 90 c1 ea 08 90 90 33 c2 88 03 90 90 61 8b 45 08 40 3d ?? ?? ?? ?? 89 45 08 } //1
		$a_01_1 = {8a 44 24 46 88 5c 24 48 88 5c 24 4b 88 5c 24 4c c6 44 24 49 2e 88 44 24 4a c6 44 24 4d 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}