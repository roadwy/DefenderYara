
rule Trojan_BAT_Noon_EANJ_MTB{
	meta:
		description = "Trojan:BAT/Noon.EANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 13 0e 11 0d 6c 28 9c 00 00 0a 28 8d 00 00 0a b7 13 0f 18 13 10 2b 1a 11 0d 11 10 5d 16 fe 01 13 11 11 11 2c 05 16 13 0e 2b 0d 00 11 10 17 d6 13 10 11 10 11 0f 31 e0 11 0e 13 12 11 12 2c 07 11 06 17 d6 13 06 00 00 11 0d 17 d6 13 0d 11 0d 20 88 13 00 00 31 a9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}