
rule Backdoor_BAT_Crysan_AHPA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AHPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 2b 28 72 ?? ?? 00 70 2b 24 2b 29 2b 2e 72 ?? ?? 00 70 2b 2a 2b 2f 2b 34 2b 35 06 16 06 8e 69 6f ?? ?? 00 0a 0c 1e 2c e3 de 44 07 2b d5 28 ?? ?? 00 0a 2b d5 6f ?? ?? 00 0a 2b d0 07 2b cf 28 ?? ?? 00 0a 2b cf 6f ?? ?? 00 0a 2b ca 07 2b c9 6f ?? ?? 00 0a 2b c4 } //3
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}