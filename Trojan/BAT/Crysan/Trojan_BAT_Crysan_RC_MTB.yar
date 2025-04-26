
rule Trojan_BAT_Crysan_RC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 02 16 fe 01 13 21 11 21 2c 06 06 17 58 0a 2b 02 16 0a 17 0b 07 16 fe 01 13 22 11 22 2c 04 16 0b 2b 0f 16 25 0b 13 23 11 23 2c 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}