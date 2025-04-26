
rule TrojanDownloader_BAT_Seraph_ABKP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {0d 09 07 6f ?? 00 00 0a 13 04 08 11 04 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 28 ?? 00 00 06 13 05 08 6f ?? 00 00 0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 13 06 de 37 09 2c 06 09 6f ?? 00 00 0a dc } //3
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}