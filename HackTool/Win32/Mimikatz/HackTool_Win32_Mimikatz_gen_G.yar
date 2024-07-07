
rule HackTool_Win32_Mimikatz_gen_G{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 01 00 c0 90 02 20 81 fe 4b 00 00 c0 90 02 40 81 fe 4b 00 00 c0 90 02 30 68 ff ff 00 00 50 90 00 } //1
		$a_03_1 = {01 00 00 c0 85 90 01 01 74 90 02 50 0f b7 06 83 f8 21 74 90 01 01 83 f8 2a 74 90 02 04 e8 90 01 01 00 00 00 eb 90 00 } //1
		$a_03_2 = {83 7c 24 04 03 75 90 02 30 59 59 85 c0 75 10 33 c0 50 50 50 68 85 04 00 00 ff 15 90 02 08 33 c0 c2 08 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule HackTool_Win32_Mimikatz_gen_G_2{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 c0 85 90 01 01 74 90 02 50 0f b7 06 83 f8 21 74 90 01 01 83 f8 2a 74 90 02 04 e8 90 01 01 00 00 00 eb 90 00 } //1
		$a_03_1 = {83 7c 24 04 03 75 90 02 30 59 59 85 c0 75 10 33 c0 50 50 50 68 85 04 00 00 ff 15 90 02 08 33 c0 c2 08 00 90 00 } //1
		$a_03_2 = {8b 85 48 ff ff ff 35 2c 17 5a e3 89 06 0f 84 90 01 04 6a 08 8d 45 ec 8b d6 5b 53 8d 4d f8 89 45 f8 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}