
rule Trojan_BAT_BitRat_NE_MTB{
	meta:
		description = "Trojan:BAT/BitRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 00 0c 00 00 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 0a 06 6f 90 01 01 00 00 0a 0b 07 6f 90 01 01 00 00 0a 0c 73 90 01 01 00 00 0a 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}