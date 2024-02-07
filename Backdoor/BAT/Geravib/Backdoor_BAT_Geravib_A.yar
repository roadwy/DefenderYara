
rule Backdoor_BAT_Geravib_A{
	meta:
		description = "Backdoor:BAT/Geravib.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 42 2d 52 41 54 2d 43 6c 69 65 6e 74 } //01 00  VB-RAT-Client
		$a_01_1 = {55 70 6c 6f 61 64 53 63 72 65 65 6e 73 68 6f 74 } //01 00  UploadScreenshot
		$a_01_2 = {4d 65 69 6e 65 56 69 63 74 69 6d 49 44 } //01 00  MeineVictimID
		$a_01_3 = {44 61 74 65 69 75 70 6c 6f 61 64 65 6e } //01 00  Dateiuploaden
		$a_01_4 = {50 00 72 00 6f 00 7a 00 65 00 73 00 73 00 4c 00 69 00 73 00 74 00 65 00 } //01 00  ProzessListe
		$a_01_5 = {49 00 6e 00 68 00 61 00 6c 00 74 00 65 00 61 00 75 00 66 00 6c 00 69 00 73 00 74 00 65 00 6e 00 } //00 00  Inhalteauflisten
		$a_00_6 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}