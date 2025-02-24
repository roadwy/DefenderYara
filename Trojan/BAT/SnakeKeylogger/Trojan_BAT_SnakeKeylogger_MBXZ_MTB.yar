
rule Trojan_BAT_SnakeKeylogger_MBXZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MBXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? ?? ?? 06 0c 04 03 6f ?? ?? ?? 0a 59 0d 03 08 09 28 ?? ?? ?? 06 00 07 17 58 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}