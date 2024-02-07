
rule Backdoor_MacOS_Leverage_A_MTB{
	meta:
		description = "Backdoor:MacOS/Leverage.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 6d 20 27 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 55 73 65 72 45 76 65 6e 74 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 55 73 65 72 45 76 65 6e 74 2e 69 63 6e 73 27 } //01 00  rm '/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns'
		$a_00_1 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 74 65 6c 6c 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 22 53 79 73 74 65 6d 20 45 76 65 6e 74 73 22 20 74 6f 20 67 65 74 20 74 68 65 20 68 69 64 64 65 6e 20 6f 66 20 65 76 65 72 79 20 6c 6f 67 69 6e 20 69 74 65 6d 27 } //01 00  osascript -e 'tell application "System Events" to get the hidden of every login item'
		$a_00_2 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 69 6e 70 75 74 20 76 6f 6c 75 6d 65 20 6f 66 20 28 67 65 74 20 76 6f 6c 75 6d 65 20 73 65 74 74 69 6e 67 73 29 27 } //01 00  osascript -e 'input volume of (get volume settings)'
		$a_00_3 = {4d 61 63 69 6e 74 6f 73 68 20 48 44 3a 55 73 65 72 73 3a 53 68 61 72 65 64 3a 75 70 2e 7a 69 70 } //01 00  Macintosh HD:Users:Shared:up.zip
		$a_02_4 = {61 77 6b 20 2d 46 27 3a 5c 74 27 20 27 7b 70 72 69 6e 74 20 90 02 02 7d 27 20 7c 20 70 61 73 74 65 20 2d 64 90 00 } //01 00 
		$a_00_5 = {73 65 72 76 65 72 56 69 73 69 62 6c 65 } //00 00  serverVisible
		$a_00_6 = {5d 04 00 } //00 7b 
	condition:
		any of ($a_*)
 
}