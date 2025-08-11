
rule Trojan_BAT_DarkTortilla_TQD_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.TQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 28 11 06 6f ?? 01 00 0a 28 ?? 00 00 0a 13 07 07 11 07 28 ?? 00 00 0a 03 28 ?? 01 00 06 b4 6f ?? 01 00 0a 00 08 17 d6 0c 00 11 06 6f ?? 01 00 0a 13 08 11 08 2d cb } //5
		$a_01_1 = {02 03 61 0b 07 0a 2b 00 06 2a } //4 ̂ୡਇ+⨆
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}