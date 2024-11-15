
rule Backdoor_BAT_Remcos_XGAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.XGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 08 17 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de 20 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}