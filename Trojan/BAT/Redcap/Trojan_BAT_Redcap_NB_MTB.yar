
rule Trojan_BAT_Redcap_NB_MTB{
	meta:
		description = "Trojan:BAT/Redcap.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_80_0 = {75 72 6c 68 61 75 73 2e 61 62 75 73 65 2e 63 68 2f 64 6f 77 6e 6c 6f 61 64 73 2f 74 65 78 74 5f 6f 6e 6c 69 6e 65 } //urlhaus.abuse.ch/downloads/text_online  01 00 
		$a_80_1 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  01 00 
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  01 00 
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  01 00 
		$a_80_4 = {4e 65 77 20 66 6f 6c 64 65 72 } //New folder  00 00 
	condition:
		any of ($a_*)
 
}