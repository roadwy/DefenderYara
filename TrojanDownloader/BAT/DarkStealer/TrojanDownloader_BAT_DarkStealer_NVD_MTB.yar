
rule TrojanDownloader_BAT_DarkStealer_NVD_MTB{
	meta:
		description = "TrojanDownloader:BAT/DarkStealer.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {20 50 c3 00 00 8d ?? ?? ?? 01 0a 20 00 04 00 00 8d ?? ?? ?? 01 0a 02 7b } //1
		$a_01_1 = {02 72 01 00 00 70 20 95 2f 00 00 73 } //1
		$a_01_2 = {57 15 a2 01 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 35 } //1
		$a_01_3 = {30 00 2e 00 74 00 63 00 70 00 2e 00 6e 00 67 00 72 00 6f 00 6b 00 2e 00 69 00 6f 00 } //1 0.tcp.ngrok.io
		$a_01_4 = {68 00 61 00 63 00 6b 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6d 00 67 00 } //1 hacked by amg
		$a_01_5 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}