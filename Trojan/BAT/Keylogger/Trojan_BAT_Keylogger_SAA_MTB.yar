
rule Trojan_BAT_Keylogger_SAA_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.SAA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 01 00 00 04 17 73 17 00 00 0a 13 05 02 7b 01 00 00 04 18 28 10 00 00 0a 00 11 05 02 08 28 04 00 00 06 6f 18 00 00 0a 00 11 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}