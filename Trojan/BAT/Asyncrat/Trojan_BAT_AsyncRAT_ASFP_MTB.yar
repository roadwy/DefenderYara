
rule Trojan_BAT_AsyncRAT_ASFP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ASFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 17 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 28 ?? 00 00 06 58 0c 08 06 8e 69 32 e3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}