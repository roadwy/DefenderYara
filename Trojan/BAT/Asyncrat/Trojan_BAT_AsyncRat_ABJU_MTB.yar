
rule Trojan_BAT_AsyncRat_ABJU_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f ?? ?? ?? 0a 0b de 11 de 0f 90 0a 3d 00 06 08 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f } //3
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}