
rule Trojan_BAT_NjRAT_PSJX_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 07 08 6f 0c 00 00 0a 17 73 90 01 03 0a 13 04 00 11 04 02 16 02 8e 69 6f 90 01 03 0a 00 11 04 6f 90 01 03 0a 00 00 de 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}