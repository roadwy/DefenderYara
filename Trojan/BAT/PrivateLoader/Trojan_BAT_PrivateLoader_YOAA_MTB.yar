
rule Trojan_BAT_PrivateLoader_YOAA_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.YOAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 72 01 00 00 70 6f 1b 00 00 0a 28 ?? 00 00 0a 0b 73 1d 00 00 0a 0c 08 07 6f 1e 00 00 0a 00 08 18 6f 1f 00 00 0a 00 08 18 6f 20 00 00 0a 00 08 6f 21 00 00 0a 0d 09 06 16 06 8e 69 6f 22 00 00 0a 13 04 08 6f 23 00 00 0a 00 28 ?? 00 00 0a 11 04 6f 24 00 00 0a 13 05 2b 00 11 05 2a } //3
		$a_01_1 = {4a 00 74 00 61 00 37 00 70 00 51 00 63 00 6c 00 43 00 45 00 6f 00 55 00 33 00 65 00 72 00 46 00 37 00 6b 00 61 00 31 00 75 00 41 00 3d 00 3d 00 } //2 Jta7pQclCEoU3erF7ka1uA==
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}