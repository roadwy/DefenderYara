
rule TrojanDownloader_Win32_Secwar_A{
	meta:
		description = "TrojanDownloader:Win32/Secwar.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 77 00 61 00 69 00 74 00 20 00 77 00 68 00 69 00 6c 00 65 00 20 00 53 00 65 00 74 00 75 00 70 00 20 00 69 00 73 00 20 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 2e 00 2e 00 2e 00 } //1 Please wait while Setup is loading...
		$a_01_1 = {53 65 63 75 72 65 57 61 72 72 69 6f 72 20 53 65 74 75 70 } //1 SecureWarrior Setup
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 65 63 75 72 65 77 61 72 72 69 6f 72 2e 63 6f 6d 2f 73 65 63 75 72 65 77 61 72 72 69 6f 72 2e 70 68 70 } //1 http://www.securewarrior.com/securewarrior.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}