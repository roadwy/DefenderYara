
rule TrojanDownloader_Win32_Darmapo{
	meta:
		description = "TrojanDownloader:Win32/Darmapo,SIGNATURE_TYPE_PEHSTR,3e 00 3e 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 63 20 53 54 4f 50 20 67 62 70 6b 6d } //01 00  sc STOP gbpkm
		$a_01_1 = {73 63 20 44 45 4c 45 54 45 20 67 62 70 6b 6d } //01 00  sc DELETE gbpkm
		$a_01_2 = {73 63 20 44 45 4c 45 54 45 20 73 6e 6d 67 72 73 76 63 } //01 00  sc DELETE snmgrsvc
		$a_01_3 = {73 63 20 44 45 4c 45 54 45 20 73 6e 73 69 64 } //01 00  sc DELETE snsid
		$a_01_4 = {73 63 20 44 45 4c 45 54 45 20 73 6e 73 6d 73 } //0a 00  sc DELETE snsms
		$a_01_5 = {5c 00 6d 00 73 00 6d 00 61 00 6e 00 2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 75 00 6e 00 73 00 65 00 72 00 69 00 76 00 63 00 65 00 } //0a 00  \msman.exe -runserivce
		$a_01_6 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 68 00 69 00 67 00 68 00 63 00 6f 00 6e 00 66 00 2e 00 73 00 79 00 73 00 } //0a 00  \drivers\highconf.sys
		$a_01_7 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 46 00 6f 00 6e 00 74 00 53 00 75 00 62 00 73 00 74 00 69 00 74 00 75 00 74 00 65 00 73 00 } //0a 00  \CurrentVersion\FontSubstitutes
		$a_01_8 = {53 00 65 00 74 00 4c 00 61 00 79 00 65 00 72 00 65 00 64 00 57 00 69 00 6e 00 64 00 6f 00 77 00 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 73 00 } //0a 00  SetLayeredWindowAttributes
		$a_01_9 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } //0a 00  InternetOpenUrlW
		$a_01_10 = {43 72 65 61 74 65 53 65 72 76 69 63 65 57 } //00 00  CreateServiceW
	condition:
		any of ($a_*)
 
}