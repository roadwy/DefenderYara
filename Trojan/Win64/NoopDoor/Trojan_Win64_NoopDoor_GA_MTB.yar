
rule Trojan_Win64_NoopDoor_GA_MTB{
	meta:
		description = "Trojan:Win64/NoopDoor.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 34 3a 31 39 3a 35 35 } //1 14:19:55
		$a_01_1 = {67 45 7a 74 49 61 74 74 7a 70 6d 50 71 52 59 49 67 63 45 6e } //1 gEztIattzpmPqRYIgcEn
		$a_01_2 = {47 61 46 74 6f 79 74 56 73 4b 65 53 57 } //1 GaFtoytVsKeSW
		$a_01_3 = {43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 CryptGenRandom
		$a_01_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_01_5 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}