
rule Trojan_BAT_Zusy_PSPO_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 74 1f 00 00 01 74 11 00 00 01 20 f7 01 00 00 20 df 01 00 00 28 90 01 03 2b 14 06 74 10 00 00 01 20 6e 01 00 00 20 69 01 00 00 28 90 01 03 2b 20 89 00 00 00 20 ac 00 00 00 28 90 01 03 2b 13 05 11 11 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}