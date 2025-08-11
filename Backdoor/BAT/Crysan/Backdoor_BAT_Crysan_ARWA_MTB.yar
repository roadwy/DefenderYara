
rule Backdoor_BAT_Crysan_ARWA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ARWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 06 28 ?? 00 00 0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 11 05 6f ?? 00 00 0a 06 11 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 02 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 73 ?? 00 00 0a 0c 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 07 de 2a } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}