
rule Backdoor_BAT_Crysan_ASAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ASAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 0c 07 08 16 7e ?? 00 00 04 6f ?? 00 00 0a 26 08 16 28 ?? 00 00 0a 26 07 16 73 ?? 00 00 0a 0d 09 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 11 04 16 11 04 8e 69 28 ?? 00 00 0a 11 04 13 05 de 1e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}