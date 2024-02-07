
rule TrojanDropper_Win32_OnLineGames_E{
	meta:
		description = "TrojanDropper:Win32/OnLineGames.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 68 7a 57 65 74 69 62 62 51 6d 63 74 6f 73 6f 68 7a 62 62 57 6d 70 6a 6f 77 73 62 62 43 79 74 74 69 70 7a 58 69 74 73 6d 6f 70 62 62 54 79 70 00 } //01 00  潓穨敗楴扢浑瑣獯桯扺坢灭潪獷扢祃瑴灩塺瑩浳灯扢祔p
		$a_01_1 = {58 33 52 43 7a 74 72 5f 53 7a 6f 76 53 69 74 78 6d 63 69 5f 4d 70 73 7a 00 } //01 00 
		$a_01_2 = {58 33 52 43 7a 74 72 5f 59 70 54 69 67 6d 73 7a 69 74 53 69 74 78 6d 63 69 56 72 79 67 4d 70 00 } //01 00  ㍘䍒瑺彲灙楔浧穳瑩楓硴捭噩祲䵧p
		$a_01_3 = {c6 06 4d c6 46 01 5a } //01 00 
		$a_01_4 = {b9 fe 00 00 00 56 f7 f9 8b 74 24 0c fe c2 85 f6 76 10 8b 44 24 08 8a 08 2a ca 32 ca 88 08 40 4e 75 f4 } //00 00 
	condition:
		any of ($a_*)
 
}