
rule Trojan_BAT_Heracles_AANU_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AANU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 72 01 00 00 70 28 90 01 01 00 00 0a 72 33 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 14 13 05 90 00 } //3
		$a_01_1 = {36 00 7a 00 37 00 73 00 73 00 63 00 5a 00 46 00 4b 00 6f 00 76 00 4b 00 33 00 2f 00 31 00 75 00 5a 00 50 00 71 00 65 00 65 00 67 00 3d 00 3d 00 } //1 6z7sscZFKovK3/1uZPqeeg==
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 ReadAsByteArrayAsync
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}