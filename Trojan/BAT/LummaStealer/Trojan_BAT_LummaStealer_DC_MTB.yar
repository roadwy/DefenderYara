
rule Trojan_BAT_LummaStealer_DC_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 07 1f 28 5a 58 13 08 28 20 00 00 0a 07 11 08 1e 6f 21 00 00 0a 17 8d 29 00 00 01 6f 22 00 00 0a 13 09 28 20 00 00 0a 11 09 6f 23 00 00 0a 28 24 00 00 0a 72 f2 00 00 70 28 25 00 00 0a 39 41 00 00 00 07 11 08 1f 14 58 28 1f 00 00 0a 13 0a 07 11 08 1f 10 58 28 1f 00 00 0a 13 0b 11 0b 8d 1d 00 00 01 80 05 00 00 04 07 11 0a 6e 7e 05 00 00 04 16 6a 11 0b 6e 28 26 00 00 0a 17 13 06 38 0e 00 00 00 11 07 17 58 13 07 11 07 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}