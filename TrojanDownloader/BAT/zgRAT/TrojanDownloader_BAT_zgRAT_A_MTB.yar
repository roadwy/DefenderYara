
rule TrojanDownloader_BAT_zgRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/zgRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d 90 01 01 00 00 01 0a 16 0b 90 00 } //2
		$a_03_1 = {06 07 02 07 91 20 90 01 03 83 28 90 01 01 00 00 06 28 90 01 02 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 90 00 } //2
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}