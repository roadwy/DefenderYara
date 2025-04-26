
rule Trojan_BAT_CryptInject_MBAJ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 08 18 6f ?? 00 00 0a 08 6f 33 00 00 0a 0a 02 13 04 06 11 04 16 11 04 8e b7 6f 34 00 00 0a 0b 07 } //1
		$a_01_1 = {42 51 6c 6d 76 47 42 65 00 00 0d 01 00 08 57 54 70 4d 6b 70 6d 78 00 00 0d 01 00 08 71 49 74 78 59 4d 4b 45 } //1
		$a_01_2 = {68 00 49 00 48 00 57 00 37 00 34 00 72 00 6e 00 37 00 50 00 66 00 44 00 7a 00 68 00 68 00 47 00 70 00 59 00 62 00 56 00 6d 00 7a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}