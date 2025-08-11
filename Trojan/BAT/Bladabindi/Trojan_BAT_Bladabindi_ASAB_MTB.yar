
rule Trojan_BAT_Bladabindi_ASAB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ASAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 2b 19 11 04 03 6f ?? 00 00 0a 17 da 33 05 16 13 04 2b 0b 11 04 17 d6 13 04 2b 03 9c 2b e4 11 05 17 d6 13 05 2b 03 0b 2b bc 11 05 11 06 31 02 2b 05 2b be 0d 2b a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}