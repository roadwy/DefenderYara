
rule Trojan_BAT_Stealer_BHAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.BHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 65 2b 66 2b 6b 2b 73 1c 2c 45 18 2c f2 06 28 90 01 01 00 00 0a 0c 90 00 } //02 00 
		$a_03_1 = {06 2b 98 28 90 01 01 00 00 2b 2b 93 28 90 01 01 00 00 2b 38 90 01 01 ff ff ff 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}