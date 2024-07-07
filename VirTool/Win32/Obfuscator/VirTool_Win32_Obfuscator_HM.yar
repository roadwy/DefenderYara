
rule VirTool_Win32_Obfuscator_HM{
	meta:
		description = "VirTool:Win32/Obfuscator.HM,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 85 28 f8 ff ff 8d 04 d0 8b 30 83 c6 10 83 68 04 10 ff 70 04 56 57 e8 63 ff ff ff 03 78 04 42 81 fa 90 01 04 75 d8 90 00 } //1
		$a_01_1 = {0f b6 07 33 45 10 88 07 47 49 85 c9 75 f2 } //1
		$a_01_2 = {8b 55 0c 8b 04 b7 31 02 ff 32 ff 75 08 e8 dc ff ff ff 8b 55 10 31 02 8b 02 8b 4d 0c 51 8b 09 89 0a 59 89 01 4e 83 fe 01 77 d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}