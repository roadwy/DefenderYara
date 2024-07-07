
rule Trojan_BAT_Heracles_EJAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 58 1b 2c e9 13 04 11 05 17 58 13 05 16 3a 52 ff ff ff 11 05 02 31 e5 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}