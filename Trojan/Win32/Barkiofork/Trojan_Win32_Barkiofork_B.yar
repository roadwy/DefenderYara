
rule Trojan_Win32_Barkiofork_B{
	meta:
		description = "Trojan:Win32/Barkiofork.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 25 64 29 20 25 2e 36 34 73 5c 25 2e 36 34 73 7c 25 2e 36 34 73 7c 25 2e 36 34 73 7c 25 2e 36 34 73 } //01 00  (%d) %.64s\%.64s|%.64s|%.64s|%.64s
		$a_01_1 = {3c 2a 2a 43 46 47 2a 2a 3e 53 74 61 72 74 75 70 } //01 00  <**CFG**>Startup
		$a_01_2 = {42 3a 55 73 65 20 2e 69 6e 69 20 66 69 6c 65 3d 31 } //01 00  B:Use .ini file=1
		$a_01_3 = {45 6e 61 62 6c 65 20 4c 6f 67 67 69 6e 67 } //01 00  Enable Logging
		$a_01_4 = {4c 6f 67 67 69 6e 67 20 46 69 6c 65 20 4e 61 6d 65 } //01 00  Logging File Name
		$a_01_5 = {50 6c 75 67 69 6e 5f 25 64 } //01 00  Plugin_%d
		$a_01_6 = {53 5b 31 36 5d 3a 4c 61 6e 67 75 61 67 65 3d 45 6e 67 6c 69 73 68 } //00 00  S[16]:Language=English
	condition:
		any of ($a_*)
 
}