
rule TrojanDownloader_Win32_Bancos_BM{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 2c bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b7 54 5a fe 2b d3 81 ea ?? ?? 00 00 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 d9 } //2
		$a_00_1 = {2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 2e 00 2e 00 2e 00 2f 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 } //1
		$a_00_2 = {63 00 6f 00 6d 00 2f 00 2e 00 2e 00 2e 00 2f 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}