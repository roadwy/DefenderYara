
rule Trojan_BAT_Marsilia_SX_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 8c 06 00 00 01 0c 07 20 12 01 00 00 20 60 f0 00 00 6a 28 1d 00 00 0a 16 28 1e 00 00 0a 28 14 00 00 06 26 08 14 72 25 00 00 70 16 8d 03 00 00 01 14 14 14 28 1f 00 00 0a 16 8c 17 00 00 01 16 28 20 00 00 0a 08 14 72 31 00 00 70 16 8d 03 00 00 01 14 14 14 28 1f 00 00 0a 16 8c 17 00 00 01 16 28 20 00 00 0a 28 21 00 00 0a 28 22 00 00 0a 2c 1a 72 3f 00 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}