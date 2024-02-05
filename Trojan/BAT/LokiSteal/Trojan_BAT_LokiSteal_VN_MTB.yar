
rule Trojan_BAT_LokiSteal_VN_MTB{
	meta:
		description = "Trojan:BAT/LokiSteal.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 07 19 8d 90 01 03 01 80 90 01 03 04 7e 90 01 03 04 16 7e 90 01 03 04 a2 7e 90 01 03 04 17 7e 90 01 03 04 a2 02 11 06 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 06 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}