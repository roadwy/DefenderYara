
rule Trojan_BAT_Crysan_KKG_MTB{
	meta:
		description = "Trojan:BAT/Crysan.KKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_81_0 = {61 62 64 6f } //02 00  abdo
		$a_81_1 = {72 72 72 72 72 72 72 72 72 72 72 72 77 65 65 72 77 } //02 00  rrrrrrrrrrrrweerw
		$a_81_2 = {65 77 65 77 77 65 71 65 77 71 65 71 77 } //02 00  ewewweqewqeqw
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //02 00  DownloadFile
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //02 00  FromBase64String
		$a_81_5 = {00 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 00 } //02 00  攀敥敥敥敥敥敥敥e
		$a_81_6 = {00 77 77 77 77 77 77 77 77 77 77 77 77 77 00 } //00 00 
	condition:
		any of ($a_*)
 
}