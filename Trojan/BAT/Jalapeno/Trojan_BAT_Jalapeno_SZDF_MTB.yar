
rule Trojan_BAT_Jalapeno_SZDF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SZDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 11 04 11 06 1f 1f 5f 62 60 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 00 08 6f ?? 00 00 0a 13 0f 2b 00 11 0f 2a } //5
		$a_03_1 = {08 11 05 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 11 05 1e 63 13 05 11 06 1e 59 13 06 00 11 06 1d fe 02 13 0c 11 0c 2d d7 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}