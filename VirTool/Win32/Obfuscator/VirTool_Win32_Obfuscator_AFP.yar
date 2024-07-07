
rule VirTool_Win32_Obfuscator_AFP{
	meta:
		description = "VirTool:Win32/Obfuscator.AFP,SIGNATURE_TYPE_PEHSTR_EXT,14 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {8a 01 84 c0 74 90 01 01 32 45 ff 2a 45 f8 fe c8 88 04 0a 90 00 } //5
		$a_01_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 4e 74 23 25 64 3a 20 25 73 3a 20 25 73 00 4b 45 59 20 3d 20 30 78 25 58 2c 20 4c 65 6e 20 3d 20 25 64 } //1
		$a_01_2 = {4c 6f 61 64 65 72 50 45 3a 23 25 64 3a 57 72 69 74 65 20 26 20 50 72 6f 74 65 63 74 20 30 78 25 58 20 61 74 20 61 64 64 72 3a 30 78 25 58 } //1 LoaderPE:#%d:Write & Protect 0x%X at addr:0x%X
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 43 72 79 70 74 6f 3a 20 4f 4b } //1 FromBase64Crypto: OK
		$a_01_4 = {4c 6f 61 64 65 72 50 45 3a 20 41 6e 74 69 64 65 62 75 67 41 6e 64 44 65 63 72 79 70 74 3d 30 78 25 58 } //1 LoaderPE: AntidebugAndDecrypt=0x%X
		$a_01_5 = {54 72 79 20 4e 74 47 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 } //1 Try NtGetContextThread
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}