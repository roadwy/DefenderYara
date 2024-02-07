
rule Backdoor_Win32_Darkmoon_AE{
	meta:
		description = "Backdoor:Win32/Darkmoon.AE,SIGNATURE_TYPE_PEHSTR_EXT,48 00 48 00 0d 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {73 74 6f 70 20 73 68 61 72 65 64 61 63 63 65 73 73 } //0a 00  stop sharedaccess
		$a_00_2 = {00 6e 65 74 2e 65 78 65 00 } //0a 00 
		$a_00_3 = {44 61 72 6b 4d 6f 6f 6e } //0a 00  DarkMoon
		$a_00_4 = {6d 61 69 6c 20 66 72 6f 6d 3a } //0a 00  mail from:
		$a_00_5 = {7b 42 41 43 4b 7d } //0a 00  {BACK}
		$a_00_6 = {43 79 62 65 72 4e 65 74 69 63 } //01 00  CyberNetic
		$a_00_7 = {4d 69 63 72 6f 73 6f 66 74 20 4d 53 4e } //01 00  Microsoft MSN
		$a_00_8 = {48 4f 4c 41 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //01 00  HOLA@hotmail.com
		$a_01_9 = {53 74 41 72 54 4c 69 53 74 46 4d } //01 00  StArTLiStFM
		$a_00_10 = {73 75 62 6a 65 63 74 3a 20 74 65 73 74 69 6e 67 } //01 00  subject: testing
		$a_00_11 = {70 72 6f 63 65 64 65 53 65 72 76 65 72 43 4d 44 } //01 00  procedeServerCMD
		$a_01_12 = {44 6d 50 61 53 73 57 72 4f 6e 47 } //00 00  DmPaSsWrOnG
	condition:
		any of ($a_*)
 
}