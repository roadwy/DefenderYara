
rule Backdoor_BAT_Geravib_A{
	meta:
		description = "Backdoor:BAT/Geravib.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 42 2d 52 41 54 2d 43 6c 69 65 6e 74 } //1 VB-RAT-Client
		$a_01_1 = {55 70 6c 6f 61 64 53 63 72 65 65 6e 73 68 6f 74 } //1 UploadScreenshot
		$a_01_2 = {4d 65 69 6e 65 56 69 63 74 69 6d 49 44 } //1 MeineVictimID
		$a_01_3 = {44 61 74 65 69 75 70 6c 6f 61 64 65 6e } //1 Dateiuploaden
		$a_01_4 = {50 00 72 00 6f 00 7a 00 65 00 73 00 73 00 4c 00 69 00 73 00 74 00 65 00 } //1 ProzessListe
		$a_01_5 = {49 00 6e 00 68 00 61 00 6c 00 74 00 65 00 61 00 75 00 66 00 6c 00 69 00 73 00 74 00 65 00 6e 00 } //1 Inhalteauflisten
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}