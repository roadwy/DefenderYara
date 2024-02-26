
rule Trojan_BAT_DCRat_RPZ_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 11 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 11 0e 11 0b 59 13 0f 07 11 09 11 0f 11 07 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}