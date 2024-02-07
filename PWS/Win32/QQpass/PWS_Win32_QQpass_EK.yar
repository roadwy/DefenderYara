
rule PWS_Win32_QQpass_EK{
	meta:
		description = "PWS:Win32/QQpass.EK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f8 0b 7c 16 83 f8 14 7f 11 83 c0 2f 0f 80 90 01 01 00 00 00 83 e8 0a e9 90 01 01 00 00 00 83 f8 15 90 00 } //01 00 
		$a_00_1 = {2f 00 53 00 54 00 41 00 52 00 54 00 20 00 51 00 51 00 55 00 49 00 4e 00 3a 00 } //01 00  /START QQUIN:
		$a_00_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 } //01 00  cmd.exe /c start C:\Windows\
		$a_00_3 = {54 00 58 00 47 00 75 00 69 00 46 00 6f 00 75 00 6e 00 64 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  TXGuiFoundation
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_QQpass_EK_2{
	meta:
		description = "PWS:Win32/QQpass.EK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 69 61 6f 66 65 6e 67 5f 61 69 51 32 30 31 30 5f } //01 00  xiaofeng_aiQ2010_
		$a_01_1 = {58 33 36 32 37 34 20 ce aa b2 bb c4 dc b6 c1 a3 a1 00 } //01 00 
		$a_01_2 = {6e 6c 6f 6f 74 74 3f 71 64 70 68 62 79 64 6f 78 68 41 77 75 78 68 3f 71 64 70 68 62 79 64 6f 78 68 41 3f 30 62 30 41 69 6c 75 76 77 6e 6c 6f 6f 77 6c 70 68 3f 71 64 70 68 62 79 64 6f 78 68 41 39 39 3f 71 64 70 68 62 79 64 6f 78 68 41 3f 30 62 30 41 64 76 73 58 75 6f 3f 71 64 70 68 62 79 64 6f 78 68 41 3f } //01 00  nloott?qdphbydoxhAwuxh?qdphbydoxhA?0b0Ailuvwnloowlph?qdphbydoxhA99?qdphbydoxhA?0b0AdvsXuo?qdphbydoxhA?
		$a_01_3 = {00 61 73 70 55 72 6c 00 26 50 61 73 73 57 6f 72 64 3d 00 3f 4e 75 6d 62 65 72 3d 00 } //00 00  愀灳牕l倦獡坳牯㵤㼀畎扭牥=
	condition:
		any of ($a_*)
 
}