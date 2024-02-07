
rule TrojanDropper_Win32_Vawtrak_A{
	meta:
		description = "TrojanDropper:Win32/Vawtrak.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 ff 0f 00 00 0d 00 40 00 00 89 45 ec ff 75 08 e8 90 01 04 59 33 d2 b9 ff 3f 00 00 f7 f1 81 c2 00 80 00 00 89 55 f0 ff 75 08 e8 90 01 04 59 89 45 f4 ff 75 08 e8 90 01 04 59 89 45 f8 ff 75 08 e8 90 01 04 59 89 45 fc ff 75 fc ff 75 f8 ff 75 f4 ff 75 f0 ff 75 ec ff 75 e8 ff 75 e4 ff 75 e0 90 00 } //01 00 
		$a_02_1 = {6a 03 59 f7 f1 83 c2 06 89 55 f8 83 65 fc 00 eb 90 01 01 8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 f8 73 1f ff 75 08 e8 90 01 04 59 33 d2 6a 1a 59 f7 f1 83 c2 61 8b 45 fc 8b 4d 10 66 89 14 41 90 00 } //01 00 
		$a_01_2 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 22 00 } //01 00  regsvr32.exe "%s"
		$a_01_3 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 00 44 3a 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 57 44 29 } //00 00  㩓䴨㭌主㭗㬻坌)㩄䄨伻䍉㭉䅇㬻圻⥄
	condition:
		any of ($a_*)
 
}