
rule Trojan_Win32_Fragtor_GA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 68 61 64 6f 77 33 64 65 63 5f 6c 69 62 76 6c 63 2e 64 6c 6c } //1 shadow3dec_libvlc.dll
		$a_01_1 = {42 49 54 46 55 43 4b 45 52 } //1 BITFUCKER
		$a_01_2 = {45 44 52 4d 55 52 44 45 52 } //1 EDRMURDER
		$a_01_3 = {49 4e 56 49 4e 53 49 4e 43 49 42 4c 45 } //1 INVINSINCIBLE
		$a_01_4 = {43 72 79 70 74 44 65 63 72 79 70 74 } //1 CryptDecrypt
		$a_01_5 = {43 72 79 70 74 44 65 72 69 76 65 4b 65 79 } //1 CryptDeriveKey
		$a_01_6 = {43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //1 CryptDestroyKey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}