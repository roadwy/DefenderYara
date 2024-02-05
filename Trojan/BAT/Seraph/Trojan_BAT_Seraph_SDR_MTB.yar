
rule Trojan_BAT_Seraph_SDR_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {13 16 2b 1e 11 16 6f 90 01 03 0a 13 3c 11 11 11 3c 11 1f 59 61 13 11 11 1f 19 11 11 58 1e 63 59 13 1f 11 16 6f 90 01 03 06 2d d9 de 0c 11 16 2c 07 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 4d 65 74 61 64 61 74 61 54 6f 6b 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}