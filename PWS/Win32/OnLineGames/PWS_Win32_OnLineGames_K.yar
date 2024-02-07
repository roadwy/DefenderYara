
rule PWS_Win32_OnLineGames_K{
	meta:
		description = "PWS:Win32/OnLineGames.K,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  搮汬䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣䐀汬敒楧瑳牥敓癲牥䐀汬湕敲楧瑳牥敓癲牥
		$a_01_1 = {49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 } //01 00  InternetShortcut
		$a_01_2 = {44 65 72 20 48 65 72 72 20 64 65 72 20 52 69 6e 67 65 20 4f 6e 6c 69 6e 65 } //01 00  Der Herr der Ringe Online
		$a_01_3 = {54 68 65 20 4c 6f 72 64 20 6f 66 20 74 68 65 20 52 69 6e 67 73 20 4f 6e 6c 69 6e 65 } //01 00  The Lord of the Rings Online
		$a_01_4 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 31 30 2e 53 79 73 4c 69 73 74 56 69 65 77 33 32 2e 61 70 70 } //01 00  WindowsForms10.SysListView32.app
		$a_01_5 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 31 30 2e 45 44 49 54 2e 61 70 70 } //01 00  WindowsForms10.EDIT.app
		$a_01_6 = {6c 61 75 6e 63 68 65 72 31 2e 75 72 6c } //01 00  launcher1.url
		$a_01_7 = {73 65 63 72 65 74 51 75 65 73 74 69 6f 6e 41 6e 73 77 65 72 } //01 00  secretQuestionAnswer
		$a_01_8 = {61 63 63 6f 75 6e 74 4e 61 6d 65 } //01 00  accountName
		$a_01_9 = {70 61 73 73 77 6f 72 64 } //00 00  password
	condition:
		any of ($a_*)
 
}