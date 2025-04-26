
rule TrojanDownloader_BAT_AsyncRAT_L_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 65 5f 44 72 6f 70 70 65 72 5f } //2 Lime_Dropper_
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 } //2 DownloadPayload
		$a_01_2 = {49 6e 73 74 61 6c 6c 50 61 79 6c 6f 61 64 } //2 InstallPayload
		$a_01_3 = {64 72 6f 70 50 61 74 68 } //2 dropPath
		$a_01_4 = {70 61 79 6c 6f 61 64 42 75 66 66 65 72 } //2 payloadBuffer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}