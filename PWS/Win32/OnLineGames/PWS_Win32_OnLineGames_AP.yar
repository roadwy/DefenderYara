
rule PWS_Win32_OnLineGames_AP{
	meta:
		description = "PWS:Win32/OnLineGames.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 44 44 2e 64 6c 6c 00 4c 70 6b 44 6c 6c } //01 00  䑄⹄汤l灌䑫汬
		$a_01_1 = {66 61 73 73 64 66 6a 66 73 64 2e 64 61 74 00 } //02 00 
		$a_01_2 = {4c 6f 61 64 44 4c 4c 2e 64 6c 6c 00 4c 70 6b 44 6c 6c } //01 00  潌摡䱄⹌汤l灌䑫汬
		$a_01_3 = {67 61 6d 65 74 65 78 74 2e 64 61 74 00 } //02 00 
		$a_03_4 = {6a 02 6a 00 68 90 03 01 01 4a 44 ff ff ff 53 e8 90 01 02 ff ff 8d 85 7c ff ff ff e8 90 00 } //02 00 
		$a_03_5 = {8a 0c 10 80 c1 90 01 01 80 f1 90 01 01 80 e9 90 01 01 8b 1d 90 01 04 88 0c 13 42 81 fa 90 01 02 00 00 75 e2 90 00 } //01 00 
		$a_01_6 = {c6 04 03 e9 40 8b ca c1 e9 00 80 e1 ff 88 0c 03 40 8b ca c1 e9 08 80 e1 ff } //00 00 
	condition:
		any of ($a_*)
 
}