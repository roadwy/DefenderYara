
rule TrojanDownloader_BAT_ArtemisLoader_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/ArtemisLoader.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 2b c6 28 ?? 00 00 06 2b c1 6f ?? 00 00 0a 2b bc 6f ?? 00 00 0a 2b b7 28 ?? 00 00 2b 2b d1 28 ?? 00 00 2b 2b cc 6f ?? 00 00 0a 2b c8 0a 2b c7 06 2b c8 } //2
		$a_03_1 = {16 2d 08 08 6f ?? 00 00 0a 13 04 de 33 07 2b cc 73 ?? 00 00 0a 2b c8 73 ?? 00 00 0a 2b c3 0d 2b c2 } //2
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}