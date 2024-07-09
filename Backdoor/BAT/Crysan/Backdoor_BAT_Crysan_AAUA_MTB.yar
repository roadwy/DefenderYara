
rule Backdoor_BAT_Crysan_AAUA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 17 58 13 03 20 0a 00 00 00 38 ?? ff ff ff 73 ?? 00 00 0a 13 0b 20 08 00 00 00 38 ?? ff ff ff 12 07 28 ?? 00 00 0a 13 0a 20 09 00 00 00 38 ?? ff ff ff 11 0b 11 0a 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 09 00 04 7b ?? 09 00 04 39 ?? fe ff ff 26 20 00 00 00 00 38 ?? fe ff ff 11 01 11 03 16 28 ?? 00 00 06 13 07 20 07 00 00 00 38 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}