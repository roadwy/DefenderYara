
rule VirTool_Win32_Obfuscator_XR{
	meta:
		description = "VirTool:Win32/Obfuscator.XR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4f 0c 8b 55 b8 8a 14 11 32 15 ?? ?? ?? ?? 88 14 01 8b 0d ?? ?? ?? ?? b8 01 00 00 00 03 c8 89 0d ?? ?? ?? ?? e9 } //1
		$a_03_1 = {b8 ff 00 00 00 66 3b c8 0f 8f 1c 01 00 00 0f bf f1 (e9 ?? ?? ??|?? ?? 81 fe 00 01) 00 00 72 02 ff d7 a1 ?? ?? ?? ?? 33 db 8a 1c 30 81 fb 00 01 00 00 72 02 ff d7 } //1
		$a_03_2 = {50 c6 45 d4 58 e8 ?? ?? ?? ?? 8d 4d d4 51 c6 45 d4 59 e8 ?? ?? ?? ?? 8d 55 d4 52 c6 45 d4 59 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}