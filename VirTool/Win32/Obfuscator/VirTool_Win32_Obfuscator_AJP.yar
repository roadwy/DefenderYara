
rule VirTool_Win32_Obfuscator_AJP{
	meta:
		description = "VirTool:Win32/Obfuscator.AJP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 00 09 41 00 03 05 3c 09 41 00 8b 0d 3c 09 41 00 8a 10 88 91 00 f9 40 00 a1 3c 09 41 00 0f be 88 00 f9 40 00 0f b6 15 04 09 41 00 33 ca 88 4d ff a1 3c 09 41 00 8a 4d ff 88 88 00 f9 40 00 8b 15 3c 09 41 00 83 c2 01 89 15 3c 09 41 00 81 3d 3c 09 41 00 5e 01 00 00 72 a6 ff 25 08 09 41 00 } //1
		$a_01_1 = {83 f9 6b 75 14 8d 0d 09 10 40 00 89 0d 00 09 41 00 8d 05 41 11 40 00 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}