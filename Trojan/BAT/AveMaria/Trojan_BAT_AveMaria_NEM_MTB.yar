
rule Trojan_BAT_AveMaria_NEM_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 11 04 3f 90 01 01 00 00 00 d0 90 01 01 00 00 01 28 07 00 00 0a 09 28 08 00 00 0a 16 8d 90 01 01 00 00 01 6f 09 00 00 0a 26 11 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}