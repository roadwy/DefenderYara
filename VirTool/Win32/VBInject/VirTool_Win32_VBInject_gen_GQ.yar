
rule VirTool_Win32_VBInject_gen_GQ{
	meta:
		description = "VirTool:Win32/VBInject.gen!GQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 04 00 "
		
	strings :
		$a_03_0 = {c1 f8 1f 33 45 90 01 01 8b 90 03 04 04 4d 90 01 01 8d 90 01 04 c1 f9 1f 33 90 03 04 04 4d 90 01 01 8d 90 01 04 3b c1 0f 8f 90 00 } //04 00 
		$a_03_1 = {8a 10 8b 45 90 01 01 56 32 10 ff 37 88 55 90 00 } //02 00 
		$a_01_2 = {8b 4d 08 03 81 f8 00 00 00 50 8b 45 08 8b 00 ff 75 08 ff 50 } //02 00 
		$a_03_3 = {83 c0 01 0f 80 90 09 0c 00 81 7d 90 01 05 7f 90 01 01 8b 45 90 00 } //02 00 
		$a_03_4 = {83 c6 01 0f 80 90 09 08 00 81 fe 90 01 04 7f 90 00 } //02 00 
		$a_03_5 = {df e0 9e 0f 87 90 01 02 00 00 d9 45 90 01 01 d8 05 90 01 04 d9 5d 90 01 01 df e0 a8 0d 0f 85 90 00 } //01 00 
		$a_03_6 = {8a 1e 32 18 ff 75 90 01 01 8b 45 90 01 01 ff 30 90 00 } //01 00 
		$a_03_7 = {c1 f9 1f 8b d1 33 c8 33 90 02 07 3b ca 0f 8f 90 00 } //01 00 
		$a_03_8 = {c7 00 e8 00 00 00 8b 45 08 8b 80 90 01 04 c7 40 04 22 00 00 00 90 00 } //01 00 
		$a_03_9 = {66 c7 00 e8 00 8b 45 08 8b 80 90 01 04 66 c7 40 02 22 00 90 00 } //01 00 
		$a_03_10 = {bf 98 3a 00 00 8b de 57 e8 90 01 04 e8 90 01 04 e8 90 01 04 8b f0 e8 90 01 04 2b f3 68 90 01 04 70 90 01 01 33 c0 3b f7 0f 9d c0 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}