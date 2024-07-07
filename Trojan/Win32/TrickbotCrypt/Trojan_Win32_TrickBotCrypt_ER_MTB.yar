
rule Trojan_Win32_TrickBotCrypt_ER_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d8 0f af 1d 90 01 04 03 de 8d 04 0b 8a 0d 90 01 04 89 54 24 90 01 01 8a 14 3a 8a 18 02 d1 8b 4c 24 90 01 01 32 da 88 18 8b 44 24 90 01 01 40 3b c1 89 44 24 90 01 01 0f 82 90 00 } //1
		$a_81_1 = {4e 38 56 59 54 76 44 48 46 4c 78 7a 35 30 67 79 6a 5a 71 5e 62 3c 67 79 55 5e 5f 26 53 66 28 33 5e 47 74 51 74 68 5f 51 42 63 58 36 37 36 24 2b 6f 29 28 73 3f 71 5a 4c 51 35 45 6f 42 71 } //1 N8VYTvDHFLxz50gyjZq^b<gyU^_&Sf(3^GtQth_QBcX676$+o)(s?qZLQ5EoBq
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}