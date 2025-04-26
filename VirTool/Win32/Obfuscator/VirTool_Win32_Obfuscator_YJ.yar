
rule VirTool_Win32_Obfuscator_YJ{
	meta:
		description = "VirTool:Win32/Obfuscator.YJ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3f 43 72 65 61 74 65 44 6c 67 4d 65 73 73 61 67 65 40 40 59 47 48 50 41 58 50 41 44 4b 7c 55 } //1 ?CreateDlgMessage@@YGHPAXPADK|U
		$a_01_1 = {73 75 38 32 61 73 64 37 79 64 69 75 73 61 68 6b 73 6a 64 68 61 69 75 73 79 38 64 37 61 73 36 79 64 69 75 61 68 73 6b } //1 su82asd7ydiusahksjdhaiusy8d7as6ydiuahsk
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 2f 00 2f 00 64 00 75 00 66 00 69 00 73 00 64 00 75 00 68 00 66 00 6b 00 6a 00 73 00 68 00 6b 00 64 00 68 00 66 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 75 00 2f 00 2f 00 73 00 64 00 75 00 66 00 79 00 69 00 75 00 23 00 39 00 38 00 37 00 39 00 37 00 33 00 34 00 } //1 https:////dufisduhfkjshkdhf.com.au//sdufyiu#9879734
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_YJ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.YJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b7 01 eb 02 b7 00 89 c6 b3 00 80 f9 47 74 3f b3 01 80 f9 45 74 38 b3 02 80 f9 46 74 12 b3 03 80 f9 4e 74 0b 80 f9 4d 0f 85 ?? ?? ?? ?? b3 04 b8 12 00 00 00 8b 55 dc 39 c2 76 25 ba 02 00 00 00 80 f9 4d 75 1b } //1
		$a_03_1 = {8b 10 85 d2 74 38 8b 4a f8 49 74 32 53 89 c3 8b 42 fc e8 ?? ?? ?? ?? 89 c2 8b 03 89 13 50 8b 48 fc e8 ?? ?? ?? ?? 58 8b 48 f8 49 7c 0e f0 ff 48 f8 75 08 8d 40 f8 e8 ?? ?? ?? ?? 8b 13 5b 89 d0 c3 } //1
		$a_03_2 = {0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 e0 46 4f 75 d7 be ?? ?? ?? ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? 30 18 4b 85 db 75 f9 40 4e 75 f0 8d 05 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d0 33 c0 5a 59 59 64 89 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}