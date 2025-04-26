
rule TrojanSpy_BAT_Stealer_MI_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_03_0 = {0a fe 0e 01 00 fe 0c 01 00 73 ?? ?? ?? 0a fe 0e 02 00 14 fe 0e 03 00 14 fe 0e 04 00 28 ?? ?? ?? 0a fe 0c 02 00 fe 0c 00 00 28 ?? ?? ?? 0a 8e 69 20 10 00 00 00 59 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 04 00 fe 0c 01 00 20 f0 ff ff ff 6a 20 02 00 00 00 6f ?? ?? ?? 0a 26 fe 0c 02 00 20 10 00 00 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 03 00 fe 0c 04 00 fe 0c 03 00 28 ?? ?? ?? 0a fe 0e 05 00 fe 0c 05 00 39 06 00 00 00 73 26 00 00 0a 7a 2a } //1
		$a_01_1 = {4d 75 74 65 78 41 63 63 65 73 73 52 75 6c 65 } //1 MutexAccessRule
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 54 72 61 6e 73 66 6f 72 6d 4d 6f 64 65 } //1 FromBase64TransformMode
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_6 = {52 65 67 69 73 74 72 79 4b 65 79 50 65 72 6d 69 73 73 69 6f 6e 43 68 65 63 6b } //1 RegistryKeyPermissionCheck
		$a_01_7 = {43 72 79 70 74 6f 4b 65 79 41 63 63 65 73 73 52 75 6c 65 } //1 CryptoKeyAccessRule
		$a_01_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_10 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}