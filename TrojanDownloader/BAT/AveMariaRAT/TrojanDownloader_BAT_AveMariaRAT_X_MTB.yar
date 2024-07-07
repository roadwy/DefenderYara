
rule TrojanDownloader_BAT_AveMariaRAT_X_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 00 06 14 14 11 08 74 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //1 SecurityProtocolType
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_4 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}