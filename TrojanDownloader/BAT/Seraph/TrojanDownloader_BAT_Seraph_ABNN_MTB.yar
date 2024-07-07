
rule TrojanDownloader_BAT_Seraph_ABNN_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.ABNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 6f 90 01 03 0a de 07 09 6f 90 01 03 0a dc 08 6f 90 01 03 0a 13 04 de 0e 90 0a 27 00 07 16 73 90 01 03 0a 73 90 00 } //3
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}