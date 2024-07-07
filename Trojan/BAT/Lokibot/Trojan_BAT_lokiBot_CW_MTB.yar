
rule Trojan_BAT_lokiBot_CW_MTB{
	meta:
		description = "Trojan:BAT/lokiBot.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 f4 00 00 0a 03 04 17 58 08 5d 91 28 f5 00 00 0a 59 06 58 06 5d d2 0d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}