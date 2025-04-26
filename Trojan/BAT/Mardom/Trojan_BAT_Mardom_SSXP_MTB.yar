
rule Trojan_BAT_Mardom_SSXP_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 1e 11 0b 6f e7 00 00 0a 13 23 11 0c 11 23 11 10 59 61 13 0c 11 10 11 0c 19 58 1e 63 59 13 10 11 0b 6f b4 00 00 06 2d d9 de 0c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}