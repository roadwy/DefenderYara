
rule Trojan_BAT_RedLine_RDV_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 33 41 6d 72 68 67 6b 43 6c 65 56 54 47 64 45 77 41 } //01 00  j3AmrhgkCleVTGdEwA
		$a_01_1 = {74 63 61 72 74 6e 6f 43 63 6e 79 73 41 74 73 75 72 54 53 57 49 79 74 69 72 75 63 65 53 6c 65 64 6f 4d 65 63 69 76 72 65 53 6d 65 74 73 79 53 33 36 37 34 39 } //01 00  tcartnoCcnysAtsurTSWIytiruceSledoMecivreSmetsyS36749
		$a_01_2 = {74 00 9c 00 38 00 30 00 91 00 91 00 6e 00 35 00 68 00 8e 00 95 00 62 00 86 00 86 00 8c 00 77 00 2e 00 96 00 89 00 9d 00 72 00 8b 00 6f 00 92 00 77 00 9f 00 8a 00 6b 00 66 00 64 00 6e 00 96 00 64 00 9c 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}