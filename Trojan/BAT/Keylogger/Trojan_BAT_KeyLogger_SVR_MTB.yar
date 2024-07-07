
rule Trojan_BAT_KeyLogger_SVR_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.SVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 0e 04 11 05 1f 10 5a 7e 0c 00 00 04 20 ff 7f 00 00 03 08 92 58 91 58 a3 21 00 00 02 0e 05 28 90 01 03 06 00 02 7e 0d 00 00 04 20 ff 7f 00 00 03 08 92 58 a3 21 00 00 02 0e 05 28 90 01 03 06 00 08 17 58 d2 0c 00 08 11 04 fe 02 16 fe 01 13 0d 11 0d 3a 40 ff ff ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}