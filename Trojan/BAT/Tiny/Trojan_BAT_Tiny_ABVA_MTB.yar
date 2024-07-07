
rule Trojan_BAT_Tiny_ABVA_MTB{
	meta:
		description = "Trojan:BAT/Tiny.ABVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 01 00 00 70 28 90 01 01 00 00 0a 72 b8 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 00 72 cc 00 00 70 72 d4 00 00 70 73 90 01 01 00 00 0a 25 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 25 17 6f 90 01 01 00 00 0a 00 28 90 01 01 00 00 0a 26 1f 0b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}