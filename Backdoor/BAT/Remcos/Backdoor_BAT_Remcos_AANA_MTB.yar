
rule Backdoor_BAT_Remcos_AANA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.AANA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 ?? 00 00 0a 72 ?? 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 28 ?? 00 00 0a 72 ?? 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7e ?? 00 00 04 19 73 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 69 0a 08 11 04 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 09 07 7e ?? 00 00 04 16 94 06 6f ?? 00 00 0a 26 72 ?? 04 00 70 13 07 72 ?? 04 00 70 13 05 07 28 ?? 00 00 06 26 11 06 2a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}