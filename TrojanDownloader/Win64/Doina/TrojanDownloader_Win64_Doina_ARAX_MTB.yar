
rule TrojanDownloader_Win64_Doina_ARAX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Doina.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 6f 73 74 5f 68 65 6c 70 65 72 2e 65 78 65 } //2 \svchost_helper.exe
		$a_01_1 = {2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //2 -DisableRealtimeMonitoring
		$a_01_2 = {75 70 64 61 74 65 2e 65 78 65 } //2 update.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}