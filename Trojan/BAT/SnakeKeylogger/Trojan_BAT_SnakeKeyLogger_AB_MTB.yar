
rule Trojan_BAT_SnakeKeyLogger_AB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 8d ?? ?? ?? 01 0c 16 } //1
		$a_03_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 6f ?? ?? ?? 0a [0-03] 58 [0-03] 59 fe 01 13 06 11 06 2c 04 16 0d 2b ?? 09 [0-03] 58 [0-04] 0d 00 11 04 17 58 13 04 11 04 02 8e 69 17 59 [0-08] fe 02 16 fe 01 13 07 11 07 2d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}