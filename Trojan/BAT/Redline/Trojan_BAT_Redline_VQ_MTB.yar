
rule Trojan_BAT_Redline_VQ_MTB{
	meta:
		description = "Trojan:BAT/Redline.VQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 08 11 09 9a 13 0a 00 06 11 0a 6f 90 01 04 13 0b 11 0b 39 08 00 00 00 00 17 0c 38 12 00 00 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 3f cd ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}