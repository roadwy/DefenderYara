
rule Trojan_BAT_DCRat_AADL_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AADL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 26 0b 16 28 90 01 01 00 00 06 0c 2b 1e 06 08 06 08 91 07 08 07 28 90 01 01 01 00 06 25 26 69 5d 91 61 d2 9c 08 1a 28 90 01 01 00 00 06 58 0c 08 06 28 90 01 01 01 00 06 25 26 69 32 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}