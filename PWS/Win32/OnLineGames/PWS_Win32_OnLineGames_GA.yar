
rule PWS_Win32_OnLineGames_GA{
	meta:
		description = "PWS:Win32/OnLineGames.GA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {70 6c 6f 72 c7 45 90 01 01 65 72 5c 53 c7 45 90 01 01 68 65 6c 6c c7 45 90 01 01 45 78 65 63 c7 45 90 01 01 75 74 65 48 c7 45 90 01 01 6f 6f 6b 73 90 00 } //01 00 
		$a_02_1 = {6a 04 ff d6 53 a3 90 01 04 ff 35 90 01 04 68 90 01 04 6a 02 ff d6 53 a3 90 01 04 ff 35 90 01 04 68 90 01 04 6a 07 ff d6 a3 90 00 } //01 00 
		$a_02_2 = {50 57 c7 45 90 01 01 6f 6b 00 00 ff 15 90 01 04 83 c4 0c 85 c0 57 75 19 ff 15 90 01 04 59 68 10 27 00 00 ff d6 90 00 } //01 00 
		$a_02_3 = {49 6e 50 72 c7 45 90 01 01 6f 63 53 65 c7 45 90 01 01 72 76 65 72 c7 45 90 01 01 33 32 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}