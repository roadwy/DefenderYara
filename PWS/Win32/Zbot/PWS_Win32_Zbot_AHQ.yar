
rule PWS_Win32_Zbot_AHQ{
	meta:
		description = "PWS:Win32/Zbot.AHQ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 8e 15 91 8e 3b 1b 1b 05 68 24 94 6b c5 88 9a 8b a2 67 f0 9f 15 ca 86 9c f3 81 72 08 9c 1c df } //02 00 
		$a_01_1 = {67 34 8e 92 a3 52 fe 96 dc ec 5a bb 92 fd 1d b6 c8 e6 3a b9 f3 bd c2 04 f2 } //01 00 
		$a_01_2 = {a6 9b 15 35 c8 f3 5e ed e9 04 85 70 36 31 f3 87 79 54 dd b9 8d 5b 95 68 } //01 00 
		$a_01_3 = {6f bb 1b b2 0d 8d b6 5f 40 2e 39 f7 8c 48 e2 f8 85 eb 03 0e 1d cb 07 aa b6 b7 } //01 00 
		$a_01_4 = {3a 5a e8 92 29 1a 7c c1 58 ae 3b b0 47 6d cf df 76 01 8f ce 65 c1 22 fd 94 54 e2 ec 83 14 76 1b } //01 00 
		$a_01_5 = {4a 5a a4 e2 79 d9 7c 8d 73 9e ed 95 2c 1f c0 fa 91 f2 40 b3 49 74 13 f9 90 4a 96 c9 60 c7 c7 17 } //00 00 
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}