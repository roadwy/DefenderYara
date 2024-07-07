
rule Backdoor_BAT_Crysan_AAXM_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 1f 20 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 08 1f 10 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0d 09 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 04 11 04 02 16 02 8e 69 6f 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a de 0b 26 09 6f 90 01 01 00 00 0a 13 05 de 2f 90 00 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {79 00 79 00 36 00 7a 00 44 00 6a 00 41 00 55 00 6d 00 62 00 42 00 30 00 39 00 70 00 4b 00 76 00 6f 00 35 00 48 00 68 00 75 00 67 00 3d 00 3d 00 } //1 yy6zDjAUmbB09pKvo5Hhug==
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}