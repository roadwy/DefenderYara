
rule Trojan_BAT_Keylogger_PSA_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {80 9b 00 00 04 73 4e 01 00 0a 80 9a 00 00 04 7e 16 ?? ?? ?? 7e 98 00 00 04 28 5f ?? ?? ?? 80 9c 00 00 04 7e ed 01 00 04 28 08 ?? ?? ?? 19 3a 8d 00 00 00 26 7e 18 ?? ?? ?? 06 72 0f 00 00 70 28 62 ?? ?? ?? 16 2c 7f 26 1e 2c 48 7e 1b ?? ?? ?? 7e 1a ?? ?? ?? 07 28 65 ?? ?? ?? 28 68 ?? ?? ?? 1b 2d 3d 26 08 8d 99 00 00 01 1d 2d 36 26 } //5
		$a_01_1 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //1 ICryptoTransform
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {44 65 72 69 76 65 42 79 74 65 73 } //1 DeriveBytes
		$a_01_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}