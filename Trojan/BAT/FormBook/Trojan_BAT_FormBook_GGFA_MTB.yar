
rule Trojan_BAT_FormBook_GGFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GGFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe 0c 04 00 fe 0c 0b 00 fe 0c 04 00 fe 0c 0b 00 28 90 01 03 06 fe 0c 0b 00 28 90 01 03 06 9c fe 0c 0b 00 20 01 00 00 00 58 fe 0e 0b 00 fe 0c 0b 00 fe 0c 04 00 28 90 01 03 06 3f c1 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}