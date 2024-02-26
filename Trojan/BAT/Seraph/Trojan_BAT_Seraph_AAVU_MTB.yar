
rule Trojan_BAT_Seraph_AAVU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 08 11 05 6f 90 01 01 00 00 0a 20 07 00 00 00 38 90 01 01 ff ff ff 38 90 01 01 ff ff ff 20 03 00 00 00 38 90 01 01 ff ff ff 11 01 11 09 16 28 90 01 01 00 00 06 13 0b 20 00 00 00 00 7e 90 01 01 00 00 04 7b 90 01 01 00 00 04 39 90 01 01 fe ff ff 26 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}