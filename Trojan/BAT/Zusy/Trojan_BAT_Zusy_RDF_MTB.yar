
rule Trojan_BAT_Zusy_RDF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 69 67 67 65 72 73 70 6f 6f 66 61 } //01 00  niggerspoofa
		$a_01_1 = {65 61 63 64 72 69 76 } //01 00  eacdriv
		$a_01_2 = {67 75 6e 61 32 42 75 74 74 6f 6e 37 5f 43 6c 69 63 6b } //00 00  guna2Button7_Click
	condition:
		any of ($a_*)
 
}