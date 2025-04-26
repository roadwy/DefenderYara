
rule Trojan_BAT_Snakelogger_KAE_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 19 00 06 07 7e ?? 00 00 04 07 91 03 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}