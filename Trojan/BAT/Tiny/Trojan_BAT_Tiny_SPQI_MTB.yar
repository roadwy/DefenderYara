
rule Trojan_BAT_Tiny_SPQI_MTB{
	meta:
		description = "Trojan:BAT/Tiny.SPQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 39 16 1f 2c 9d 11 39 17 6f 90 01 03 0a 13 13 11 13 8e 69 8d 90 01 03 01 13 14 16 13 15 2b 15 11 14 11 15 11 13 11 15 9a 28 90 01 03 0a 9c 11 15 17 58 13 15 11 15 11 13 8e 69 32 e3 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}