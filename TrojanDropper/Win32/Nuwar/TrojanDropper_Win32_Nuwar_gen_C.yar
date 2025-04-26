
rule TrojanDropper_Win32_Nuwar_gen_C{
	meta:
		description = "TrojanDropper:Win32/Nuwar.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c e8 74 04 3c e9 75 0f 8b 46 01 2b c7 03 45 fc 8d 44 30 fb 89 47 01 03 5d fc 03 7d fc 03 75 fc 83 fb 05 72 c2 2b f7 83 ee 05 89 77 01 c6 07 e9 } //1
		$a_03_1 = {8b 0e 8b d8 8b 01 ff 50 14 50 53 ff 15 ?? ?? ?? ?? 8b 0e 8b 11 50 ff 12 8b 0e 8b 01 ff 50 04 47 83 ff ?? 72 ?? 68 ?? ?? ?? ?? ff 15 } //1
		$a_03_2 = {8d 41 1b ff d0 85 c0 7c 13 8b 07 a3 ?? ?? ?? ?? 8b 06 a3 ?? ?? ?? ?? b8 03 00 00 40 5f 5e eb 21 ff 75 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}