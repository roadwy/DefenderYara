
rule Trojan_BAT_Crysan_ASAN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ASAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 02 16 07 16 07 8e 69 28 90 01 03 0a 00 06 03 6f 90 01 03 0a 00 06 07 6f 90 01 03 0a 00 73 0f 00 00 0a 0c 00 08 06 6f 90 01 03 0a 17 73 11 00 00 0a 13 04 00 11 04 02 07 8e 69 02 8e 69 07 8e 69 59 90 00 } //2
		$a_01_1 = {79 00 65 00 64 00 48 00 61 00 73 00 68 00 41 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 } //1 yedHashAlgorithm
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}