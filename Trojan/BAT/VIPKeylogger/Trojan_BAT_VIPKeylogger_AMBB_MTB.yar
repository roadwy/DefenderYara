
rule Trojan_BAT_VIPKeylogger_AMBB_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 16 02 7b ?? 00 00 04 6f ?? 01 00 0a 28 ?? 01 00 0a 02 7b ?? 00 00 04 25 2d 16 26 02 02 fe ?? ?? 01 00 06 73 ?? 01 00 0a 25 0b 7d ?? 00 00 04 07 28 ?? 00 00 2b 06 fe ?? ?? 01 00 06 73 ?? 01 00 0a 28 ?? 00 00 2b 2a } //5
		$a_03_1 = {0a 59 0a 06 19 fe 04 16 fe 01 0b 07 2c 34 00 02 7b ?? 00 00 04 19 8d ?? 00 00 01 25 16 0f 01 28 ?? 01 00 0a 9c 25 17 0f 01 28 ?? 01 00 0a 9c 25 18 0f 01 28 ?? 01 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}