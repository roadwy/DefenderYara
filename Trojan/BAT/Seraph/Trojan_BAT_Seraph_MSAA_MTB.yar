
rule Trojan_BAT_Seraph_MSAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.MSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0a 2b 23 00 14 0b 28 90 01 02 00 06 0b 06 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 16 07 8e 69 6f 90 01 02 00 0a de 03 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}