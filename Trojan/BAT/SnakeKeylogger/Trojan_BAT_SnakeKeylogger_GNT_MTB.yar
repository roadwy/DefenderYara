
rule Trojan_BAT_SnakeKeylogger_GNT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 72 09 0b 00 70 06 72 09 0b 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 9d 00 08 17 58 0c 08 02 fe 04 0d 09 2d d5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}