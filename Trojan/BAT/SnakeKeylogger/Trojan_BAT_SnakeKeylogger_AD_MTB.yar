
rule Trojan_BAT_SnakeKeylogger_AD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 7d 2f 00 00 04 06 20 48 34 55 0e 5a 20 91 3e c5 e7 61 2b bc 02 03 7d 33 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}