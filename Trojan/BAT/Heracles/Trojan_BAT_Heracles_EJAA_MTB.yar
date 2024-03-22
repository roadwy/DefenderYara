
rule Trojan_BAT_Heracles_EJAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 58 1b 2c e9 13 04 11 05 17 58 13 05 16 3a 52 ff ff ff 11 05 02 31 e5 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}