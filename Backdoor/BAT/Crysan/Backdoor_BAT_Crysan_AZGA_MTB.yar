
rule Backdoor_BAT_Crysan_AZGA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AZGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a dd } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}