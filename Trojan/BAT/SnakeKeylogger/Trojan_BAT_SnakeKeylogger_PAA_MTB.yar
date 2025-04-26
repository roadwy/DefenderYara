
rule Trojan_BAT_SnakeKeylogger_PAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 1b 11 0e 8f 05 00 00 01 25 47 11 0e 1f 1f 5a d2 61 d2 52 11 0e 17 58 13 0e 11 0e 11 08 75 ?? 00 00 1b 8e 69 32 d4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}