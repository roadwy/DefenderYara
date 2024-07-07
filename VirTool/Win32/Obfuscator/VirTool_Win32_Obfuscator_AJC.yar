
rule VirTool_Win32_Obfuscator_AJC{
	meta:
		description = "VirTool:Win32/Obfuscator.AJC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b e5 58 8d 28 33 c0 8b c4 74 ff 20 } //1
		$a_03_1 = {8b e5 59 8d 29 33 c9 8b cc 74 ff 21 55 8b fd 33 ec 33 ef 83 ec 90 01 01 90 05 04 06 56 57 53 52 51 50 2b c0 74 ff c0 e8 90 00 } //1
		$a_01_2 = {b3 cd a1 b1 e5 fb 53 fa 2e ae 81 2b 5f db d7 1a 4e 31 62 31 65 bc b7 97 cb 11 43 6f a3 9d 97 14 48 f1 23 ed 21 7e 77 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}