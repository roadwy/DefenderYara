
rule TrojanDownloader_Win32_GuloaderCrypt_SN_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f8 fc ff d0 fc e8 90 01 04 83 75 90 01 01 00 b9 00 00 00 00 83 34 24 00 83 04 24 00 ff 34 0a fc fc 81 34 24 90 01 04 83 34 24 00 83 6d 90 01 01 00 8f 04 08 83 34 24 00 fc 83 e9 fc 83 45 90 01 01 00 ff 45 90 01 01 ff 4d 90 01 01 81 f9 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_GuloaderCrypt_SN_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_02_0 = {ff 32 0f 38 0b e3 0f 38 0b e3 83 c2 04 0f 38 01 e3 0f 38 01 e3 bb 90 01 04 0f 38 08 e3 0f 38 01 e3 31 1c 24 90 90 0f 38 01 e3 8f 04 01 90 90 0f 38 0b e3 40 0f 38 0b e3 0f 38 08 e3 40 0f 38 08 e3 0f 38 0b e3 40 90 90 0f 38 08 e3 40 0f 38 08 e3 0f 38 0b e3 be 90 01 04 0f 38 08 e3 0f 38 01 e3 39 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}