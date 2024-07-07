
rule Trojan_BAT_Keylogger_NL_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 57 00 00 04 06 7e 56 00 00 04 02 07 6f 28 00 00 0a 7e 27 00 00 04 07 7e 27 00 00 04 8e 69 5d 91 61 28 ca 00 00 06 28 cf 00 00 06 26 07 17 58 0b 07 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}