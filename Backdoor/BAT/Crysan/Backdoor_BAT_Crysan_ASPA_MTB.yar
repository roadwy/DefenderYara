
rule Backdoor_BAT_Crysan_ASPA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ASPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 91 0c 08 18 28 ?? 00 00 06 0c 08 03 59 07 59 20 ff 00 00 00 5f d2 0c 08 66 d2 0c 06 07 08 9c 07 17 58 0b } //5
		$a_03_1 = {0a 25 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 0b dd } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}