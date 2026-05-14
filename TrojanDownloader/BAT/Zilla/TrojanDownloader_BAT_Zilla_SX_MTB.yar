
rule TrojanDownloader_BAT_Zilla_SX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Zilla.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 9a 13 06 11 06 72 ?? ?? 00 70 6f ?? 00 00 0a 2c 04 17 0c 2b 4d 08 2c 4a 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 16 31 3b 11 06 17 8d 72 00 00 01 25 16 } //30
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 50 61 79 32 50 61 79 6c 6f 61 64 41 73 79 6e 63 } //10 DownloadAndExecutePay2PayloadAsync
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}