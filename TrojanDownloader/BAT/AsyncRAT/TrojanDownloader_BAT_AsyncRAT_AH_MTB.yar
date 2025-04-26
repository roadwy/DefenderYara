
rule TrojanDownloader_BAT_AsyncRAT_AH_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 42 62 48 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 BBbH.g.resources
		$a_01_1 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 31 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //2 /C choice /C Y /N /D Y /T 1 & Del
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}