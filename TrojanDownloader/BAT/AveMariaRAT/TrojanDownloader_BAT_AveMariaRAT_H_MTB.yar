
rule TrojanDownloader_BAT_AveMariaRAT_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 0a 06 16 06 8e 69 28 90 01 01 00 00 0a 02 06 28 90 01 01 00 00 0a 7d 90 01 01 00 00 04 2a 90 00 } //2
		$a_03_1 = {0a 0a 06 03 73 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b de 90 00 } //2
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}