
rule TrojanDownloader_BAT_Seraph_ABI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {1e 5b 6f 30 ?? ?? 0a 6f ?? ?? ?? 0a 08 17 6f ?? ?? ?? 0a 07 08 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 04 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a de 0c 11 04 2c 07 11 04 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 13 05 de 14 } //3
		$a_03_1 = {09 08 6f 23 ?? ?? 0a 08 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 04 de 0d } //3
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}