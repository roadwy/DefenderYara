
rule Backdoor_WinNT_Phdet_gen_A{
	meta:
		description = "Backdoor:WinNT/Phdet.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 c7 41 0c 0f 84 8b 4d 0c c7 41 0e 14 00 00 00 } //02 00 
		$a_03_1 = {66 81 38 ff 25 75 10 8b 40 02 b9 90 01 04 87 08 89 0d 90 00 } //02 00 
		$a_03_2 = {83 f8 05 59 59 75 0b 80 7d 90 01 01 b8 75 05 8b 46 01 90 00 } //02 00 
		$a_01_3 = {81 3e 25 ff 0f 00 74 14 03 f8 03 f0 81 ff 00 01 00 00 72 dc 32 c0 5f 5e c9 c2 08 00 8b 46 0a 8d 44 06 0e 80 78 07 e8 } //02 00 
		$a_03_4 = {66 39 46 06 89 45 08 76 20 6a 01 68 90 01 04 57 e8 90 01 02 ff ff 84 c0 75 18 0f b7 46 06 90 00 } //01 00 
		$a_03_5 = {8b 45 08 03 c7 50 8d 85 f0 fe ff ff 50 e8 90 01 04 47 3b 7b 04 90 00 } //01 00 
		$a_01_6 = {52 00 75 00 6c 00 65 00 73 00 44 00 61 00 74 00 61 00 } //00 00  RulesData
	condition:
		any of ($a_*)
 
}