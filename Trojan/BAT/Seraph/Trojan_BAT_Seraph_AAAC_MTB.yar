
rule Trojan_BAT_Seraph_AAAC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {14 0a 00 73 90 01 01 00 00 0a 0b 28 90 01 01 00 00 06 0a de 07 07 6f 90 01 01 00 00 0a dc 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0a de 03 26 de d9 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}