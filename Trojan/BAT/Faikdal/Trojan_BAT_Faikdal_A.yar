
rule Trojan_BAT_Faikdal_A{
	meta:
		description = "Trojan:BAT/Faikdal.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2e 00 63 00 6f 00 6d 00 90 02 20 68 00 90 02 18 74 00 90 02 18 74 00 90 02 18 70 00 90 02 18 3a 00 90 02 18 2f 00 90 02 18 2f 00 90 00 } //01 00 
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 63 66 69 6c 65 } //01 00  downloadcfile
		$a_01_2 = {6b 69 6c 6c 6f 74 68 65 72 } //01 00  killother
		$a_01_3 = {73 61 76 65 74 6f 6c 6f 67 } //00 00  savetolog
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Faikdal_A_2{
	meta:
		description = "Trojan:BAT/Faikdal.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 6d 00 6c 00 90 02 20 68 00 90 02 18 74 00 90 02 18 74 00 90 02 18 70 00 90 02 18 3a 00 90 02 18 2f 00 90 02 18 2f 00 90 00 } //01 00 
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 63 66 69 6c 65 } //01 00  downloadcfile
		$a_01_2 = {6b 69 6c 6c 6f 74 68 65 72 } //01 00  killother
		$a_01_3 = {73 61 76 65 74 6f 6c 6f 67 } //00 00  savetolog
	condition:
		any of ($a_*)
 
}