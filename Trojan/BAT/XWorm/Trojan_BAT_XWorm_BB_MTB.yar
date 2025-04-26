
rule Trojan_BAT_XWorm_BB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 6f 1c 00 00 0a 0a 06 18 5b 8d 76 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 90 00 00 0a 1f 10 28 96 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}