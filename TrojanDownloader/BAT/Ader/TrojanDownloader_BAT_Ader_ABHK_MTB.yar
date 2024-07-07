
rule TrojanDownloader_BAT_Ader_ABHK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.ABHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b 31 16 2b 31 2b 36 2b 3b 2b 06 2b 07 2b 08 de 14 09 2b f7 08 2b f6 6f 14 00 00 0a 2b f1 09 6f 17 00 00 0a dc 18 2c 09 2b 1d 6f 15 00 00 0a 13 04 de 4e 07 } //2
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}