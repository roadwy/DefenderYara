
rule Trojan_BAT_AveMaria_RDF_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 53 68 6f 72 74 63 75 74 43 53 2e 57 69 6e } //01 00  GlobalShortcutCS.Win
		$a_01_1 = {42 6f 6e 64 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 } //01 00  Bond Technologies
		$a_01_2 = {41 64 64 4e 65 77 48 6f 74 4b 65 79 } //01 00  AddNewHotKey
		$a_01_3 = {62 74 6e 53 69 6d 75 6c 61 74 65 5f 43 6c 69 63 6b } //00 00  btnSimulate_Click
	condition:
		any of ($a_*)
 
}