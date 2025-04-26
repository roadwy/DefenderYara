
rule Trojan_BAT_SnakeKeylogger_PPBH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PPBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 06 7e 04 00 00 04 06 91 05 06 28 ?? ?? ?? 0a 04 6f ?? ?? ?? 0a 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d cf } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}