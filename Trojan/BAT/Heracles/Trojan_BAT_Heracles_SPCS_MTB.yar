
rule Trojan_BAT_Heracles_SPCS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 91 18 59 20 90 01 03 00 5f d2 9c 11 07 17 58 13 07 11 07 07 8e 69 32 e2 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}