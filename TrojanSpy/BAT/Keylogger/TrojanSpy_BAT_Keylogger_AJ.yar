
rule TrojanSpy_BAT_Keylogger_AJ{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 75 70 74 6d 72 } //01 00  startuptmr
		$a_01_1 = {52 65 6d 6f 74 65 43 6f 6d 6d 61 6e 64 73 } //01 00  RemoteCommands
		$a_01_2 = {50 72 69 6e 74 53 63 72 65 65 6e 74 6d 72 } //01 00  PrintScreentmr
		$a_01_3 = {41 6c 6c 69 6e 4f 6e 65 74 6d 72 } //01 00  AllinOnetmr
		$a_01_4 = {2d 00 20 00 23 00 23 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6c 00 69 00 73 00 74 00 20 00 23 00 23 00 20 00 4f 00 66 00 20 00 20 00 23 00 23 00 23 00 } //01 00  - ## Process list ## Of  ###
		$a_01_5 = {2d 00 2d 00 2d 00 2d 00 2d 00 20 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 2d 00 2d 00 2d 00 2d 00 2d 00 } //01 00  ----- Keyboard logger -----
		$a_01_6 = {2d 00 2d 00 2d 00 2d 00 2d 00 20 00 56 00 69 00 63 00 74 00 69 00 6d 00 27 00 73 00 20 00 49 00 6e 00 66 00 6f 00 20 00 2d 00 2d 00 2d 00 2d 00 2d 00 } //01 00  ----- Victim's Info -----
		$a_01_7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_8 = {5d 04 00 00 } //f8 14 
	condition:
		any of ($a_*)
 
}