
rule Trojan_BAT_Seraph_DHAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.DHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0d 02 18 5d 2d 07 28 90 01 01 00 00 0a 2b 05 28 90 01 01 00 00 0a 09 28 90 01 01 00 00 0a 2b 12 02 16 2f 08 16 28 90 01 01 00 00 0a 2b 06 16 28 90 01 01 00 00 0a 09 28 90 01 01 00 00 0a 13 05 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}