
rule TrojanDownloader_BAT_AsyncRAT_N_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {20 ff ff 00 00 0a 02 6f ?? 00 00 0a 0b 16 0c } //1
		$a_03_1 = {07 08 93 28 ?? 00 00 06 ?? 59 0d 06 09 } //1
		$a_01_2 = {09 06 59 0d 2b } //1
		$a_01_3 = {07 08 09 d1 9d 08 17 58 0c 08 07 8e 69 } //1
		$a_01_4 = {00 00 04 20 00 01 00 00 14 14 03 74 } //1
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}