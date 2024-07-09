
rule Trojan_BAT_Barys_PSCZ_MTB{
	meta:
		description = "Trojan:BAT/Barys.PSCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {04 11 06 28 06 00 00 06 13 07 11 07 11 05 6f 20 ?? ?? ?? 1f 20 0d 15 6a 13 08 28 21 ?? ?? ?? 13 09 06 11 07 6f 22 ?? ?? ?? 16 73 23 ?? ?? ?? 13 0a 7e 24 ?? ?? ?? 11 09 17 73 23 ?? ?? ?? 13 0b } //5
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_01_3 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //1 ICryptoTransform
		$a_01_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}