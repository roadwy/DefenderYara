
rule Trojan_BAT_CryptInject_SPQP_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 11 06 58 47 52 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d7 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}