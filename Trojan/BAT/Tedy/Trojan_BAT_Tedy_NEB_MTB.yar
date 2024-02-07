
rule Trojan_BAT_Tedy_NEB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {5a 6f 73 5a 61 70 6f 73 6c 65 6e 4e 61 52 61 64 6e 6f 6d 4d 6a 65 73 74 75 43 6f 6c 75 6d 6e } //05 00  ZosZaposlenNaRadnomMjestuColumn
		$a_01_1 = {67 65 74 5f 69 7a 6e 6f 73 42 65 7a 50 44 56 43 6f 6c 75 6d 6e } //05 00  get_iznosBezPDVColumn
		$a_01_2 = {5a 69 72 73 4c 6f 63 61 6c 2e 65 78 65 } //05 00  ZirsLocal.exe
		$a_01_3 = {48 6f 75 73 65 4f 66 43 61 72 64 73 } //04 00  HouseOfCards
		$a_01_4 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //04 00  aspnet_wp.exe
		$a_01_5 = {77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  w3wp.exe
	condition:
		any of ($a_*)
 
}