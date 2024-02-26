
rule Trojan_MacOS_Amos_L_MTB{
	meta:
		description = "Trojan:MacOS/Amos.L!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 6f 73 74 20 2f 73 65 6e 64 6c 6f 67 20 68 74 74 70 2f 31 2e 31 } //01 00  post /sendlog http/1.1
		$a_00_1 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 64 69 73 70 6c 61 79 20 64 69 61 6c 6f 67 } //01 00  osascript -e 'display dialog
		$a_00_2 = {66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 63 68 72 6f 6d 65 } //01 00  find-generic-password -ga 'chrome
		$a_00_3 = {70 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 70 61 73 73 77 6f 72 64 } //01 00  please enter your password
		$a_00_4 = {61 63 74 69 76 61 74 65 69 67 6e 6f 72 69 6e 67 6f 74 68 65 72 61 70 70 73 3a } //00 00  activateignoringotherapps:
	condition:
		any of ($a_*)
 
}