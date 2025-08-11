
rule Trojan_BAT_SnakeKeylogger_EHGU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EHGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 08 9a 09 08 17 58 6c 09 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a ?? ?? ?? ?? ?? 03 5a a1 00 09 17 58 0d 09 02 fe 04 13 04 11 04 2d d4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}