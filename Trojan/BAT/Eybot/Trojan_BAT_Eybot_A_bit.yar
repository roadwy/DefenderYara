
rule Trojan_BAT_Eybot_A_bit{
	meta:
		description = "Trojan:BAT/Eybot.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {45 79 65 42 6f 74 53 65 72 76 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 45 79 65 42 6f 74 53 65 72 76 65 72 2e 70 64 62 } //01 00  EyeBotServer\obj\Debug\EyeBotServer.pdb
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 63 00 2d 00 74 00 75 00 6e 00 65 00 2e 00 63 00 68 00 2f 00 67 00 65 00 74 00 69 00 70 00 2e 00 70 00 68 00 70 00 } //01 00  http://www.pc-tune.ch/getip.php
		$a_01_3 = {5c 00 73 00 74 00 65 00 61 00 6d 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 65 00 78 00 65 00 } //00 00  \steamconfig.exe
	condition:
		any of ($a_*)
 
}