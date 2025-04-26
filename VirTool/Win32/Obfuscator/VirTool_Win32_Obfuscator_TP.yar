
rule VirTool_Win32_Obfuscator_TP{
	meta:
		description = "VirTool:Win32/Obfuscator.TP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 50 00 6c 00 61 00 74 00 5c 00 69 00 6c 00 6c 00 42 00 6f 00 5c 00 6d 00 62 00 6f 00 6d 00 42 00 5c 00 6f 00 6d 00 62 00 6f 00 6d 00 6f 00 73 00 50 00 5c 00 6c 00 61 00 74 00 69 00 6c 00 6c 00 6f 00 73 00 50 00 6c 00 42 00 5c 00 6f 00 6d 00 62 00 6f 00 6d 00 42 00 6f 00 6d 00 62 00 6f 00 6e 00 42 00 61 00 2e 00 76 00 62 00 70 00 } //1 C:\Plat\illBo\mbomB\ombomosP\latillosPlB\ombomBombonBa.vbp
		$a_01_1 = {01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 2c 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 00 00 00 00 40 00 1e } //1
		$a_01_2 = {42 6f 6d 6d 56 42 35 21 } //1 BommVB5!
		$a_01_3 = {52 b9 58 00 00 00 89 45 e4 ff d6 50 e8 56 07 00 00 8d 45 e8 b9 5b 00 00 00 50 ff d6 50 e8 45 07 00 00 8d 4d e8 51 b9 50 00 00 00 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}