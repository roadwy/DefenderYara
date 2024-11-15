
rule Trojan_BAT_Heracles_ZSAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 02 73 ?? 01 00 0a 0c 00 08 07 16 73 ?? 01 00 0a 0d 02 8e 69 17 d6 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 01 00 0a 13 05 12 04 11 05 28 ?? 00 00 2b 00 11 04 0a de 24 } //4
		$a_01_1 = {7a 00 64 00 67 00 64 00 7a 00 2e 00 64 00 72 00 7a 00 64 00 65 00 7a 00 64 00 73 00 7a 00 6f 00 64 00 7a 00 75 00 64 00 72 00 7a 00 64 00 63 00 65 00 64 00 73 00 7a 00 64 00 } //1 zdgdz.drzdezdszodzudrzdcedszd
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}