
rule TrojanDownloader_Win32_GuloaderCrypt_MA_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 45 20 ff 4d 20 83 04 24 90 01 01 48 83 34 24 90 1b 00 83 75 20 90 1b 00 39 08 75 e9 90 00 } //1
		$a_03_1 = {f8 83 34 24 90 01 01 ff 34 0a 83 34 24 90 1b 00 83 45 20 90 1b 00 81 34 24 90 01 04 f8 83 04 24 90 1b 00 8f 04 08 83 34 24 90 1b 00 83 34 24 90 1b 00 83 c1 90 01 01 83 75 20 90 1b 00 f8 81 f9 90 01 04 75 c9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}