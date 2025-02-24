
rule Trojan_BAT_LummaC_AUKA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AUKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 13 36 02 11 31 91 13 36 11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 02 11 31 11 36 9c 11 31 17 58 13 31 } //3
		$a_03_1 = {11 2d 17 58 28 ?? 00 00 0a 11 2f 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2d 11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 11 2f 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e 73 29 00 00 0a 13 32 11 32 11 2b 11 2e 91 6f ?? 00 00 0a 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 32 16 } //2
		$a_01_2 = {65 41 54 4e 50 73 4a 78 6d 68 38 6d 70 37 61 55 59 64 } //1 eATNPsJxmh8mp7aUYd
		$a_01_3 = {65 52 74 6f 55 69 6b 51 41 55 6c 66 6d 72 63 58 68 50 } //1 eRtoUikQAUlfmrcXhP
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}