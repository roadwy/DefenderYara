
rule VirTool_Win32_Obfuscator_QG{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 54 3e ff 09 e9 } //1
		$a_01_1 = {3d f0 35 05 00 e9 } //1
		$a_01_2 = {68 20 10 dc ba e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_QG_2{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 05 00 00 "
		
	strings :
		$a_11_0 = {8d 59 41 13 e9 01 } //1
		$a_68_1 = {e2 26 6d e9 01 00 04 11 8b 42 18 e9 01 00 04 11 0f } //1536
		$a_01_2 = {00 04 11 8b 04 88 e9 00 00 78 4e 00 00 04 00 03 00 03 00 00 01 00 14 01 fe 57 e7 67 5e 12 12 aa a3 17 13 0e e8 39 17 f7 57 1c 1c d2 01 00 14 01 25 5e e8 86 39 53 0c 1e e7 15 f5 72 31 53 22 2b 15 13 4a 78 01 00 11 01 } //3255
		$a_33_3 = {3a 27 15 1a b2 fe 07 15 0e 06 3d 33 00 00 e7 48 00 00 01 00 44 00 a3 c7 0f 93 ec 44 f2 0b 0f ac ac ea ec ed f2 3f 88 74 78 6a 99 c3 da d1 31 bc 1e ac 0b fe 46 77 8f c7 17 77 e3 0f 0f 93 ec 44 f2 0b 0f ac ac ea ec ed f2 3f 88 74 78 6a 99 c3 da d1 31 bc 1e ac 0b fe 46 77 5d 04 00 00 60 7e 02 80 5c 24 00 00 62 7e 02 80 00 00 01 00 08 00 0e 00 ad 61 52 65 64 62 } //-26908
		$a_73_4 = {72 2e 43 00 00 01 40 05 82 70 00 04 00 80 10 00 00 41 28 3a b6 9d 8e 2c 36 0c 1f cf 68 00 00 00 00 5d 04 00 00 62 7e 02 80 5c 24 00 00 63 7e 02 80 00 00 01 00 08 00 0e 00 ad 61 52 65 64 62 72 6f 77 73 65 72 2e 44 00 00 01 40 05 82 70 00 04 00 80 10 00 00 3c 33 63 0a 92 64 3f 7e 07 92 0d 3d 00 00 00 00 5d 04 00 00 63 7e 02 80 5c 1e 00 00 64 7e 02 80 00 00 } //28530
	condition:
		((#a_11_0  & 1)*1+(#a_68_1  & 1)*1536+(#a_01_2  & 1)*3255+(#a_33_3  & 1)*-26908+(#a_73_4  & 1)*28530) >=5
 
}
rule VirTool_Win32_Obfuscator_QG_3{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 57 e7 67 5e 12 12 aa a3 17 13 0e e8 39 17 f7 57 1c 1c d2 } //1
		$a_01_1 = {25 5e e8 86 39 53 0c 1e e7 15 f5 72 31 53 22 2b 15 13 4a 78 } //1
		$a_01_2 = {e4 96 78 33 15 3a 27 15 1a b2 fe 07 15 0e 06 3d 33 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}