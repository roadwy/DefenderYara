
rule Backdoor_BAT_Popiidor_A{
	meta:
		description = "Backdoor:BAT/Popiidor.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 61 6e 64 6c 65 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //01 00  handleDownloadAndExecuteCommand
		$a_01_1 = {68 61 6e 64 6c 65 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  handleDownloadFile
		$a_01_2 = {68 61 6e 64 6c 65 44 72 69 76 65 73 } //01 00  handleDrives
		$a_01_3 = {68 61 6e 64 6c 65 4b 69 6c 6c 50 72 6f 63 65 73 73 } //01 00  handleKillProcess
		$a_01_4 = {68 61 6e 64 6c 65 56 69 73 69 74 57 65 62 73 69 74 65 } //01 00  handleVisitWebsite
		$a_01_5 = {68 61 6e 64 6c 65 4d 6f 75 73 65 43 6c 69 63 6b } //01 00  handleMouseClick
		$a_01_6 = {68 61 6e 64 6c 65 52 65 6d 6f 74 65 44 65 73 6b 74 6f 70 } //01 00  handleRemoteDesktop
		$a_01_7 = {68 61 6e 64 6c 65 53 74 61 72 74 50 72 6f 63 65 73 73 } //01 00  handleStartProcess
		$a_01_8 = {53 54 41 52 54 55 50 4b 45 59 00 48 49 44 45 46 49 4c 45 00 } //01 00  呓剁啔䭐奅䠀䑉䙅䱉E
		$a_01_9 = {75 72 6c 00 72 75 6e 68 69 64 64 65 6e 00 } //00 00  牵l畲桮摩敤n
		$a_00_10 = {78 42 01 00 07 } //00 07 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Popiidor_A_2{
	meta:
		description = "Backdoor:BAT/Popiidor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 00 30 00 7d 00 20 00 7b 00 31 00 7d 00 20 00 7b 00 32 00 7d 00 20 00 42 00 69 00 74 00 } //01 00  {0} {1} {2} Bit
		$a_01_1 = {2d 00 43 00 48 00 45 00 43 00 4b 00 20 00 26 00 20 00 50 00 49 00 4e 00 47 00 20 00 2d 00 6e 00 20 00 32 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 45 00 58 00 49 00 54 00 } //01 00  -CHECK & PING -n 2 127.0.0.1 & EXIT
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {68 61 6e 64 6c 65 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //01 00  handleDownloadAndExecuteCommand
		$a_01_4 = {68 61 6e 64 6c 65 4b 69 6c 6c 50 72 6f 63 65 73 73 } //01 00  handleKillProcess
		$a_01_5 = {68 61 6e 64 6c 65 56 69 73 69 74 57 65 62 73 69 74 65 } //01 00  handleVisitWebsite
		$a_01_6 = {74 72 79 55 41 43 54 72 69 63 6b } //01 00  tryUACTrick
		$a_01_7 = {24 24 24 45 4d 50 54 59 24 24 24 24 } //00 00  $$$EMPTY$$$$
		$a_00_8 = {87 10 00 00 } //b6 c0 
	condition:
		any of ($a_*)
 
}