
rule Backdoor_BAT_Remcos_EMAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.EMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 1e 02 11 04 9a 28 ?? 00 00 0a 1f 14 da 13 05 08 11 05 b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}