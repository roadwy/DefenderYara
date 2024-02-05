
rule TrojanDownloader_Win32_GuloaderCrypt_SM_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuloaderCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff d0 0f 46 c0 0f 42 c0 ba 90 01 04 0f 43 c0 0f 4b c0 81 c2 90 01 04 0f 46 c0 0f 42 c0 b9 90 01 04 0f 43 c0 0f 43 c0 8b 1c 0a 0f 44 c0 0f 43 c0 81 f3 90 01 04 0f 44 c0 0f 43 c0 31 1c 08 0f 46 c0 0f 4b c0 49 0f 47 c0 0f 42 c0 49 0f 43 c0 0f 44 c0 49 0f 42 c0 0f 4b c0 49 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}