
rule Trojan_BAT_SnakeLogger_AIZA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.AIZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 0e 04 0e 06 0e 08 17 1f 20 28 ?? ?? 00 06 0a 06 0e 05 0e 07 1f 40 23 66 66 66 66 66 66 e6 3f 28 ?? ?? 00 06 0b 16 0d 2b b8 02 03 04 06 07 17 28 ?? ?? 00 06 06 07 0e 06 0e 08 1f 0c 17 28 ?? ?? 00 06 18 0d 2b 9b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}