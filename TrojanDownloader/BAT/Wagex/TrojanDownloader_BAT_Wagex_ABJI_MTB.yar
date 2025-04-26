
rule TrojanDownloader_BAT_Wagex_ABJI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Wagex.ABJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {13 05 18 2c f6 18 2c 2b 07 08 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 11 06 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a de 0c 11 06 2c 07 11 06 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 13 07 16 2d bd } //4
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}