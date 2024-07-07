
rule TrojanDownloader_BAT_AsyncRAT_BT_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 7e 90 01 01 00 00 04 07 91 61 d2 6f 90 01 01 00 00 0a 07 17 58 0b 07 7e 90 01 01 00 00 04 8e 69 90 00 } //2
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}