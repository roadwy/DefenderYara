
rule Backdoor_BAT_Minerbot_A{
	meta:
		description = "Backdoor:BAT/Minerbot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 63 65 63 75 74 65 } //01 00  downloadAndExcecute
		$a_01_1 = {74 6d 67 72 43 68 65 63 6b } //01 00  tmgrCheck
		$a_01_2 = {61 70 70 53 68 6f 72 74 63 75 74 54 6f 53 74 61 72 74 75 70 } //01 00  appShortcutToStartup
		$a_01_3 = {2f 00 63 00 6d 00 64 00 2e 00 70 00 68 00 70 00 } //01 00  /cmd.php
		$a_01_4 = {2f 00 43 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 2f 00 74 00 72 00 20 00 25 00 75 00 73 00 65 00 72 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 25 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 } //00 00  /C schtasks /create /tn \System\SecurityServiceUpdate /tr %userprofile%\AppData\Roaming\Windows\
		$a_00_5 = {5d 04 00 } //00 0b 
	condition:
		any of ($a_*)
 
}