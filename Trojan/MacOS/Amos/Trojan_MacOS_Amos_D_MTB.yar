
rule Trojan_MacOS_Amos_D_MTB{
	meta:
		description = "Trojan:MacOS/Amos.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {e8 ec 02 00 00 e8 6a 28 00 00 e8 3f 2d 00 00 e8 7e 30 00 00 e8 a4 37 00 00 e8 ad 40 00 00 48 8d 35 bd 0f 01 00 48 8d 15 f3 79 01 00 48 8d 9d 78 ff ff ff 48 89 df } //1
		$a_00_1 = {73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 20 7c 20 61 77 6b } //1 security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk
		$a_00_2 = {6f 73 61 73 63 72 69 70 74 20 2d 65 20 27 64 69 73 70 6c 61 79 20 64 69 61 6c 6f 67 } //1 osascript -e 'display dialog
		$a_00_3 = {2f 46 69 6c 65 47 72 61 62 62 65 72 2f } //1 /FileGrabber/
		$a_00_4 = {48 6f 73 74 3a 20 61 6d 6f 73 2d 6d 61 6c 77 61 72 65 2e 72 75 } //1 Host: amos-malware.ru
		$a_00_5 = {50 4f 53 54 20 2f 73 65 6e 64 6c 6f 67 20 48 54 54 50 2f 31 2e 31 } //1 POST /sendlog HTTP/1.1
		$a_00_6 = {61 63 74 69 76 61 74 65 49 67 6e 6f 72 69 6e 67 4f 74 68 65 72 41 70 70 73 3a } //1 activateIgnoringOtherApps:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}