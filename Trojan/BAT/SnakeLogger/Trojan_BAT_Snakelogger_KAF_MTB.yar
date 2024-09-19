
rule Trojan_BAT_Snakelogger_KAF_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 19 00 02 06 7e ?? 00 00 04 06 91 03 06 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}