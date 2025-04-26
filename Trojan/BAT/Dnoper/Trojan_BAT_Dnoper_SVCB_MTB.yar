
rule Trojan_BAT_Dnoper_SVCB_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.SVCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1f 2b 20 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d de 1a 08 2b df 06 2b de 6f ?? 00 00 0a 2b d9 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}