
rule Trojan_BAT_Seraph_AAXX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {14 0a 00 28 90 01 01 00 00 06 0a 06 16 06 8e 69 28 90 01 01 00 00 0a 06 0b de 03 26 de e8 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}