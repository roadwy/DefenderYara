
rule Trojan_BAT_CrimsonRat_PSEC_MTB{
	meta:
		description = "Trojan:BAT/CrimsonRat.PSEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 73 29 00 00 0a 0a 73 25 00 00 06 0b 1b 8d 3b 00 00 01 0c 06 08 16 1b 6f 2a 00 00 0a 26 07 08 6f 2b 00 00 06 16 6a 0d 16 13 06 2b 1d 06 6f 2b 00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 0d 11 06 17 58 13 06 11 06 1e 32 de } //5
		$a_01_1 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //1 GetEnumerator
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}