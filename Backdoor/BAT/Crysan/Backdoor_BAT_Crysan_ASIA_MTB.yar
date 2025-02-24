
rule Backdoor_BAT_Crysan_ASIA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ASIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 2d 29 2b 45 72 ?? ?? 00 70 2b 41 2b 46 2b 4b 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 16 2d de 16 2d 23 08 6f ?? 00 00 0a 0d 16 2d 19 16 2d ce 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 1e } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}