
rule VirTool_Win32_Injector_gen_BF{
	meta:
		description = "VirTool:Win32/Injector.gen!BF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {81 7d fc 68 01 00 00 7d 3f 8b 45 08 33 c9 8a 08 8b 55 0c 33 c0 8a 02 f7 d0 23 c8 } //1
		$a_03_1 = {53 56 57 89 65 e8 (c7 45 fc 00 00 00 00|83 65 fc 00) f3 64 f1 90 03 07 04 c7 45 fc ff ff ff ff 83 4d fc ff eb } //1
		$a_01_2 = {83 7d fc 00 74 0b 8b 45 fc 83 e8 01 89 45 fc eb ef } //1
		$a_03_3 = {83 45 0c 28 0f b7 40 06 39 45 08 90 13 8b 45 0c 03 43 3c 8d ?? 18 f8 00 00 00 } //1
		$a_01_4 = {6a 40 68 00 30 00 00 ff 70 50 ff 70 34 ff } //1
		$a_03_5 = {40 00 ff e2 5a 90 09 05 00 52 8d 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}