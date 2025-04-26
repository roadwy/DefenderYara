
rule Trojan_Win32_Emotet_GM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 00 42 00 4d 00 63 00 46 00 64 00 61 00 75 00 6f 00 } //1 fBMcFdauo
		$a_01_1 = {43 00 72 00 79 00 70 00 74 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1 CryptEncrypt
		$a_01_2 = {4c 00 61 00 79 00 76 00 58 00 42 00 63 00 4f 00 70 00 70 00 64 00 67 00 7a 00 43 00 67 00 6e 00 6e 00 63 00 41 00 } //1 LayvXBcOppdgzCgnncA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}