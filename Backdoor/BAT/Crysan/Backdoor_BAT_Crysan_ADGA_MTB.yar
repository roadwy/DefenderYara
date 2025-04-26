
rule Backdoor_BAT_Crysan_ADGA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ADGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {26 2b 46 72 ?? ?? 00 70 2b 42 2b 47 2b 4c 72 ?? ?? 00 70 2b 48 2b 4d 1a 2c 0c 2b 52 6f ?? ?? 00 0a 0b 14 0c } //3
		$a_03_1 = {07 08 16 08 8e 69 6f ?? ?? 00 0a 0d 1c 2c c5 de 35 06 2b b7 28 ?? ?? 00 0a 2b b7 6f ?? ?? 00 0a 2b b2 06 2b b1 28 ?? ?? 00 0a 2b b1 } //2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}