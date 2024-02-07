
rule TrojanDownloader_BAT_Qhost_E{
	meta:
		description = "TrojanDownloader:BAT/Qhost.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 21 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 } //01 00 
		$a_01_1 = {75 72 6c 61 00 75 72 6c 62 00 75 72 6c 63 00 75 72 6c 64 } //01 00 
		$a_01_2 = {66 72 6d 41 64 6d 69 6e 69 73 74 72 61 44 65 73 63 61 72 67 61 00 41 64 6d 69 6e 69 73 74 72 61 44 65 73 63 61 72 67 61 } //00 00  牦䅭浤湩獩牴䑡獥慣杲a摁業楮瑳慲敄捳牡慧
	condition:
		any of ($a_*)
 
}