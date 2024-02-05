
rule Trojan_BAT_NjRat_NECO_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {a2 00 11 0f 1f 0a 11 05 08 17 28 90 01 01 00 00 0a a2 00 11 0f 28 90 01 01 00 00 0a 13 0e 08 17 d6 0c 00 08 09 fe 02 16 fe 01 13 11 11 11 3a 44 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}