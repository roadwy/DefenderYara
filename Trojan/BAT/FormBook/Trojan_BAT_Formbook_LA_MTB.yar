
rule Trojan_BAT_Formbook_LA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_80_0 = {2f 2f 31 30 37 2e 31 37 32 2e 33 31 2e 31 37 39 2f 35 30 30 } ////107.172.31.179/500  01 00 
		$a_80_1 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  01 00 
		$a_80_3 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  01 00 
		$a_80_4 = {4d 6f 63 6b } //Mock  00 00 
	condition:
		any of ($a_*)
 
}