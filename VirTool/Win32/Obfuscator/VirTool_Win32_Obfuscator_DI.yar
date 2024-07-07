
rule VirTool_Win32_Obfuscator_DI{
	meta:
		description = "VirTool:Win32/Obfuscator.DI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 57 56 53 e8 0d 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 68 70 65 86 b1 90 01 02 00 00 00 ff d0 e8 17 00 00 00 52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 00 50 68 ff 1f 7c c9 e8 90 01 01 00 00 00 ff d0 0b c0 74 07 8c c9 0a ed 75 01 90 01 01 e8 9d ff ff ff 8b 5c 24 fc 66 33 db 8b c3 03 40 3c 0f b7 50 14 8d 54 10 18 8b 42 34 03 c3 05 90 01 02 00 00 8b cb 41 50 51 68 2f 6f 06 10 e8 90 01 01 00 00 00 54 54 6a 40 ff 72 30 ff 72 34 01 1c 24 ff d0 58 59 58 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}