
rule TrojanDownloader_Win32_Colomsi_A{
	meta:
		description = "TrojanDownloader:Win32/Colomsi.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 61 74 65 72 43 6f 6d 6d 75 6e 69 74 79 } //1 CheaterCommunity
		$a_01_1 = {50 72 6f 6a 65 63 74 73 5c 49 6d 53 6f 43 4f 4f 4f 4f 4c } //1 Projects\ImSoCOOOOL
		$a_01_2 = {2f 00 67 00 65 00 68 00 2d 00 69 00 6e 00 73 00 2e 00 6b 00 7a 00 2f 00 64 00 6c 00 2f 00 77 00 72 00 61 00 72 00 33 00 38 00 30 00 64 00 2e 00 65 00 78 00 65 00 } //1 /geh-ins.kz/dl/wrar380d.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}