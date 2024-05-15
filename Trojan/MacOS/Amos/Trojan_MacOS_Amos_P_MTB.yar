
rule Trojan_MacOS_Amos_P_MTB{
	meta:
		description = "Trojan:MacOS/Amos.P!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 64 69 73 70 6c 61 79 20 64 69 61 6c 6f 67 } //01 00  osascript -e 'display dialog
		$a_00_1 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 63 68 72 6f 6d 65 27 20 7c 20 61 77 6b 20 27 7b 70 72 69 6e 74 20 24 32 7d 27 } //01 00  security 2>&1 > /dev/null find-generic-password -ga 'chrome' | awk '{print $2}'
		$a_00_2 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 74 65 6c 6c 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 22 54 65 72 6d 69 6e 61 6c 22 20 74 6f 20 63 6c 6f 73 65 20 66 69 72 73 74 20 77 69 6e 64 6f 77 27 20 26 20 65 78 69 74 } //01 00  osascript -e 'tell application "Terminal" to close first window' & exit
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 43 6f 6f 6b 69 65 73 2f 43 6f 6f 6b 69 65 73 2e 62 69 6e 61 72 79 63 6f 6f 6b 69 65 73 } //01 00  /Library/Cookies/Cookies.binarycookies
		$a_00_4 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 73 65 74 20 64 65 73 74 69 6e 61 74 69 6f 6e 46 6f 6c 64 65 72 50 61 74 68 20 74 6f 20 28 70 61 74 68 20 74 6f 20 68 6f 6d 65 20 66 6f 6c 64 65 72 20 61 73 20 74 65 78 74 29 } //00 00  osascript -e 'set destinationFolderPath to (path to home folder as text)
	condition:
		any of ($a_*)
 
}