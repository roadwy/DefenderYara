
rule Trojan_BAT_CryptInject_MBEN_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 02 18 d6 13 02 38 90 01 01 00 00 00 11 00 02 11 02 90 00 } //01 00 
		$a_01_1 = {02 11 06 91 11 01 61 11 00 11 03 91 61 13 05 } //01 00 
		$a_03_2 = {62 02 03 04 18 6f 90 01 01 00 00 0a 1f 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}