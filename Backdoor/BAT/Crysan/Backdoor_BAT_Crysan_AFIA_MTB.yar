
rule Backdoor_BAT_Crysan_AFIA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AFIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 00 07 18 6f ?? 00 00 0a 00 00 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 00 02 08 28 ?? 00 00 06 0a de 30 00 de 14 08 14 fe 01 16 fe 01 0d 09 2c 07 } //3
		$a_03_1 = {08 02 16 02 8e b7 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 00 00 de 14 08 14 fe 01 16 fe 01 0d 09 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}