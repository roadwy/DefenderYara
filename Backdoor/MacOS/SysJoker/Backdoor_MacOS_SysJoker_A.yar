
rule Backdoor_MacOS_SysJoker_A{
	meta:
		description = "Backdoor:MacOS/SysJoker.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 75 70 64 61 74 65 2e 70 6c 69 73 74 } //02 00  /Library/LaunchAgents/com.apple.update.plist
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 4d 61 63 4f 73 53 65 72 76 69 63 65 73 00 2f 4c 69 62 72 61 72 79 2f 53 79 73 74 65 6d 4e 65 74 77 6f 72 6b } //01 00 
		$a_00_2 = {61 64 64 54 6f 53 74 61 74 75 70 } //01 00  addToStatup
		$a_00_3 = {77 65 6c 63 6f 6d 65 20 74 6f 20 65 78 74 65 6e 61 6c 20 61 70 70 } //01 00  welcome to extenal app
		$a_00_4 = {4f 58 67 62 37 37 57 4e 62 55 39 30 76 79 55 62 5a 41 75 63 66 7a 79 30 65 46 31 48 71 74 42 4e 62 6b 58 69 51 36 53 53 62 71 75 75 76 46 50 55 65 70 71 55 45 6a 55 53 51 49 44 41 51 41 42 } //01 00  OXgb77WNbU90vyUbZAucfzy0eF1HqtBNbkXiQ6SSbquuvFPUepqUEjUSQIDAQAB
		$a_00_5 = {2f 61 70 69 2f 61 74 74 61 63 68 00 2f 61 70 69 2f 72 65 71 2f 72 65 73 00 74 6f 6b 65 6e 3d } //00 00 
		$a_00_6 = {5d 04 00 00 } //a0 fb 
	condition:
		any of ($a_*)
 
}