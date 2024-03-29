
rule TrojanSpy_Win32_Banker_AIZ{
	meta:
		description = "TrojanSpy:Win32/Banker.AIZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 8e 9b 01 00 00 bb 01 00 00 00 8d 45 f4 50 b9 01 00 00 00 8b d3 8b 45 fc e8 } //01 00 
		$a_03_1 = {68 e0 93 04 00 e8 90 01 03 ff 6a 00 8d 95 90 01 03 ff b8 90 01 03 00 e8 90 01 03 ff 8b 85 90 01 03 ff e8 90 01 03 ff 50 e8 90 01 03 ff e8 90 01 03 ff eb 90 04 01 02 23 32 90 00 } //01 00 
		$a_03_2 = {63 6d 64 20 2f 6b 20 00 90 01 06 90 02 03 43 90 04 01 04 23 25 2a 40 3a 90 04 01 04 23 25 2a 40 5c 90 04 01 04 23 25 2a 40 90 00 } //00 00 
		$a_00_3 = {78 d4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banker_AIZ_2{
	meta:
		description = "TrojanSpy:Win32/Banker.AIZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 04 00 "
		
	strings :
		$a_01_0 = {5c 6b 65 65 70 73 33 32 2e 65 78 65 00 } //02 00 
		$a_01_1 = {4d 34 71 75 31 6e 34 2e 00 } //02 00 
		$a_01_2 = {44 34 74 33 2e 2e 2e 2e 3a 00 } //02 00  㑄㍴⸮⸮:
		$a_01_3 = {54 69 6d 65 2e 2e 2e 2e 3a 00 } //02 00  楔敭⸮⸮:
		$a_01_4 = {4e 33 72 76 30 73 30 2e 2e 2e 2e 2e 3a 00 } //01 00  ㍎癲猰⸰⸮⸮:
		$a_01_5 = {44 41 54 45 2e 2e 2e 2e 3a 00 } //01 00  䅄䕔⸮⸮:
		$a_01_6 = {6a 6f 68 6e 79 2d 64 61 40 75 6f 6c 2e 63 6f 6d 2e 62 72 } //01 00  johny-da@uol.com.br
		$a_01_7 = {74 6f 64 61 69 6e 66 72 6f 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  todainfro@gmail.com
		$a_01_8 = {24 70 61 69 70 61 69 20 6e 6f 65 6c 20 69 6e 66 6f 72 24 } //01 00  $paipai noel infor$
		$a_01_9 = {61 62 72 6f 75 6e 65 6c 73 61 6e 74 6f 73 } //01 00  abrounelsantos
		$a_01_10 = {69 6e 66 6f 2e 6a 70 67 00 } //01 00 
		$a_01_11 = {69 6e 66 6f 2e 62 6d 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}