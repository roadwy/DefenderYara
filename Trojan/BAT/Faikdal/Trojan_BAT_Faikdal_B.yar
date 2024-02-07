
rule Trojan_BAT_Faikdal_B{
	meta:
		description = "Trojan:BAT/Faikdal.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 63 66 69 6c 65 } //01 00  downloadcfile
		$a_01_1 = {6b 69 6c 6c 6f 74 68 65 72 } //01 00  killother
		$a_01_2 = {73 61 76 65 74 6f 6c 6f 67 } //00 00  savetolog
	condition:
		any of ($a_*)
 
}