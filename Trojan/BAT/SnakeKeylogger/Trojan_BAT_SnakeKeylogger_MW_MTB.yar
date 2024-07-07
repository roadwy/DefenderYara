
rule Trojan_BAT_SnakeKeylogger_MW_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 17 8c 90 01 01 00 00 01 a2 25 17 18 8c 90 01 01 00 00 01 a2 25 18 19 8c 90 01 01 00 00 01 a2 25 16 28 90 01 03 0a 28 90 01 03 06 74 90 01 03 1b 6f 90 01 03 0a a2 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}