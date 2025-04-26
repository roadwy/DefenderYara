
rule Trojan_BAT_Androm_A_MTB{
	meta:
		description = "Trojan:BAT/Androm.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 7e 01 00 00 04 8e 69 fe 04 2d 01 2a 06 0b 1f 0b 0c 07 08 5d 2c 03 16 2b 01 17 16 fe 03 2c 14 7e 01 00 00 04 06 7e 01 00 00 04 06 91 1d 59 1f 09 59 d2 9c 06 25 0b 0d 17 25 0c 13 04 11 04 2c d1 09 11 04 58 0a 2b b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}