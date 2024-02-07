
rule PWS_BAT_Stimilini_R{
	meta:
		description = "PWS:BAT/Stimilini.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 20 53 74 65 61 6c 65 72 20 35 2e 30 00 } //01 00 
		$a_01_1 = {53 74 65 61 6d 46 6f 6c 64 65 72 00 } //01 00  瑓慥䙭汯敤r
		$a_01_2 = {55 70 6c 6f 61 64 46 69 6c 65 00 } //01 00 
		$a_01_3 = {53 74 65 61 6d 57 6f 72 6b 65 72 00 } //00 00  瑓慥坭牯敫r
	condition:
		any of ($a_*)
 
}