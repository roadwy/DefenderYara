
rule Trojan_MacOS_Amos_N_MTB{
	meta:
		description = "Trojan:MacOS/Amos.N!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 70 61 73 73 77 6f 72 64 } //1 Please enter your password
		$a_00_1 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 64 69 73 70 6c 61 79 20 64 69 61 6c 6f 67 } //1 osascript -e 'display dialog
		$a_00_2 = {2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 63 68 72 6f 6d 65 27 } //1 /dev/null find-generic-password -ga 'chrome'
		$a_00_3 = {2f 66 69 6c 65 67 72 61 62 62 65 72 2f } //1 /filegrabber/
		$a_00_4 = {68 74 74 70 3a 2f 2f [0-15] 2f 73 65 6e 64 6c 6f 67 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}