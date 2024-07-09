
rule VirTool_Win32_Obfuscator_ABN{
	meta:
		description = "VirTool:Win32/Obfuscator.ABN,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 88 a4 00 00 00 83 f9 05 77 ?? 83 b8 a8 00 00 00 02 90 09 05 00 a1 } //1
		$a_03_1 = {8d 4d f4 51 ff 75 fc ff 75 cc 57 ff 75 c8 6a 02 ff d0 85 c0 78 ?? 83 7d f4 00 } //1
		$a_01_2 = {33 c0 f7 c1 00 00 00 04 74 05 b8 00 02 00 00 f7 c1 00 00 00 20 74 22 f7 c1 00 00 00 40 74 0c 85 c9 79 04 83 c8 40 c3 83 c8 20 c3 } //1
		$a_01_3 = {6e 74 64 6c 6c 00 00 00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 52 74 6c 41 63 71 75 69 72 65 50 65 62 4c 6f 63 6b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}