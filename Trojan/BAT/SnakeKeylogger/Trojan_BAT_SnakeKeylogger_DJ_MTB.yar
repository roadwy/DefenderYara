
rule Trojan_BAT_SnakeKeylogger_DJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 02 08 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 d1 28 ?? ?? ?? 0a 13 04 06 11 04 6f ?? ?? ?? 0a 26 07 03 6f ?? ?? ?? 0a 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}