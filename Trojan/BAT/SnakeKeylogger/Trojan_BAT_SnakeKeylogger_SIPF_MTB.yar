
rule Trojan_BAT_SnakeKeylogger_SIPF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SIPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 18 5b 8d 25 00 00 01 0a 16 0b 11 06 1f 32 93 20 40 d9 00 00 59 13 05 2b b9 00 06 07 72 3d 04 00 70 03 07 18 5a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 1a 62 72 3d 04 00 70 03 07 18 5a 17 58 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 60 d2 9c 16 13 05 2b 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}