
rule Trojan_BAT_Moloterae_A{
	meta:
		description = "Trojan:BAT/Moloterae.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 75 00 65 00 65 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 3f 00 71 00 3d 00 7b 00 73 00 65 00 61 00 72 00 63 00 68 00 54 00 65 00 72 00 6d 00 73 00 7d 00 } //01 00  http://search.ueep.com/?q={searchTerms}
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6e 00 61 00 74 00 74 00 6c 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 66 00 61 00 76 00 69 00 63 00 6f 00 6e 00 2e 00 69 00 63 00 6f 00 } //01 00  http://www.nattly.com/favicon.ico
		$a_01_2 = {6d 00 61 00 69 00 6c 00 52 00 75 00 53 00 70 00 75 00 74 00 6e 00 69 00 6b 00 2e 00 64 00 6c 00 6c 00 } //00 00  mailRuSputnik.dll
	condition:
		any of ($a_*)
 
}