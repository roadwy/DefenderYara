
rule VirTool_Win32_Obfuscator_CR{
	meta:
		description = "VirTool:Win32/Obfuscator.CR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb ff ff ff 77 64 8b 83 19 00 00 88 8b 44 48 10 0f b6 40 02 f7 d0 83 e0 01 8b d8 68 f6 fb c3 00 e8 00 00 00 00 83 2c 24 33 8b f4 83 c6 04 ff e6 } //fe ff 
		$a_00_1 = {6d 00 6f 00 62 00 69 00 6c 00 65 00 45 00 78 00 20 00 50 00 72 00 6f 00 66 00 65 00 73 00 73 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 54 00 6f 00 6f 00 6c 00 } //fe ff 
		$a_01_2 = {4c 00 55 00 54 00 43 00 52 00 45 00 41 00 54 00 4f 00 52 00 41 00 42 00 4f 00 55 00 54 00 46 00 4f 00 52 00 4d 00 } //00 00 
	condition:
		any of ($a_*)
 
}