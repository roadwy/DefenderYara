
rule Trojan_BAT_DarkCloud_AQBA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AQBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 04 28 ?? 00 00 06 00 00 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 13 04 11 04 2d bf } //3
		$a_03_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}