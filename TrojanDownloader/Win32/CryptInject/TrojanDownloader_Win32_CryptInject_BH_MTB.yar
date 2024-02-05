
rule TrojanDownloader_Win32_CryptInject_BH_MTB{
	meta:
		description = "TrojanDownloader:Win32/CryptInject.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 2e 32 31 31 39 35 2e 63 6f 6d 2f 6a 6d 78 2e 74 78 74 } //01 00 
		$a_01_1 = {7a 68 65 67 65 68 61 69 7a 68 65 6e 62 7a 64 61 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00 
		$a_01_3 = {55 50 58 30 } //01 00 
		$a_01_4 = {55 50 58 31 } //00 00 
	condition:
		any of ($a_*)
 
}