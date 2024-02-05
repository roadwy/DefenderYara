
rule Trojan_BAT_BitRat_NEB_MTB{
	meta:
		description = "Trojan:BAT/BitRat.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f 15 00 00 0a 06 18 6f 16 00 00 0a 72 90 01 01 00 00 70 28 06 00 00 06 0d 06 6f 17 00 00 0a 09 16 09 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}