
rule Trojan_BAT_SnakeKeylogger_EANK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EANK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0a 94 13 0b 11 04 11 0b 19 5a 11 0b 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 0a 17 58 13 0a 11 0a 11 09 } //5
		$a_02_1 = {11 07 11 07 1f 11 5a 11 07 18 62 61 ?? ?? ?? ?? ?? 60 9e 11 07 17 58 13 07 11 07 06 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_02_1  & 1)*5) >=10
 
}