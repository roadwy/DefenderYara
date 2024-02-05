
rule Trojan_BAT_CryptInject_PB_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 17 d2 13 34 11 17 1e 63 d1 13 17 11 15 11 09 91 13 28 11 15 11 09 90 02 04 61 90 01 03 58 61 11 34 61 d2 9c 11 28 13 1f 90 01 03 58 13 09 11 09 11 24 32 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}