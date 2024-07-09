
rule Trojan_BAT_SnakeKeylogger_NVD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 7e ?? ?? ?? 04 5d 91 0a 16 0b 02 03 28 ?? ?? ?? 06 0c 06 04 58 0d 08 09 59 04 5d 0b 02 03 7e ?? ?? ?? 04 5d 07 d2 9c 02 13 04 11 04 } //1
		$a_03_1 = {04 5d 91 0a 06 7e ?? ?? ?? 04 03 1f 16 5d 6f ?? ?? ?? 0a 61 0b 07 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}