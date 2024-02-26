
rule Trojan_BAT_Seraph_AAVQ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 02 11 02 91 72 90 01 01 00 00 70 28 90 01 01 00 00 06 59 d2 9c 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00  ReadAsByteArrayAsync
	condition:
		any of ($a_*)
 
}