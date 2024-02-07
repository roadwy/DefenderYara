
rule TrojanSpy_BAT_Crime_B{
	meta:
		description = "TrojanSpy:BAT/Crime.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 74 00 3a 00 } //01 00  Passwort:
		$a_01_1 = {53 00 74 00 65 00 61 00 6c 00 65 00 72 00 } //01 00  Stealer
		$a_01_2 = {46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00 } //01 00  FileZilla\recentservers.xml
		$a_01_3 = {47 65 74 50 69 64 67 69 6e } //01 00  GetPidgin
		$a_01_4 = {47 65 74 53 74 65 61 6d 55 73 65 72 6e 61 6d 65 } //01 00  GetSteamUsername
		$a_01_5 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //01 00  get_Computer
		$a_01_6 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //00 00  get_WebServices
	condition:
		any of ($a_*)
 
}