
rule Trojan_BAT_CryptInject_DC_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 76 00 69 00 65 00 77 00 65 00 72 00 2c 00 20 00 64 00 65 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72 00 20 00 26 00 20 00 72 00 65 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72 00 } //1 Resource viewer, decompiler & recompiler
		$a_01_1 = {52 00 65 00 73 00 48 00 61 00 63 00 6b 00 } //1 ResHack
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_4 = {49 73 43 72 79 70 74 65 64 } //1 IsCrypted
		$a_01_5 = {67 65 74 5f 49 73 57 6f 72 6b 73 74 61 74 69 6f 6e } //1 get_IsWorkstation
		$a_01_6 = {65 6e 63 72 79 70 74 65 64 44 61 74 61 } //1 encryptedData
		$a_01_7 = {5a 69 70 41 6e 64 45 6e 63 72 79 70 74 } //1 ZipAndEncrypt
		$a_01_8 = {5a 69 70 53 74 72 65 61 6d } //1 ZipStream
		$a_01_9 = {4e 65 74 7a 53 74 61 72 74 65 72 } //1 NetzStarter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}