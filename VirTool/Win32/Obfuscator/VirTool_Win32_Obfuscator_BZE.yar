
rule VirTool_Win32_Obfuscator_BZE{
	meta:
		description = "VirTool:Win32/Obfuscator.BZE,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 1b 33 c9 8d 81 ?? ?? ?? ?? 8a 10 80 f2 ?? 80 ea ?? 41 88 10 81 f9 00 2c 00 00 72 90 09 07 00 80 3d ?? ?? ?? ?? 4d } //1
		$a_03_1 = {b9 4d 5a 00 00 dc 25 ?? ?? ?? ?? d9 1d ?? ?? ?? ?? 66 39 08 75 dd 53 8b 58 3c 03 d8 81 3b 50 45 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}