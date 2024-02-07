
rule TrojanDownloader_Win64_ThirdEye_SK_MTB{
	meta:
		description = "TrojanDownloader:Win64/ThirdEye.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {75 72 6c 3d 73 68 6c 61 6c 61 6c 61 2e 72 75 } //01 00  url=shlalala.ru
		$a_81_1 = {75 72 6c 3d 6b 61 6c 75 67 61 2d 6e 65 77 73 2e 72 75 } //02 00  url=kaluga-news.ru
		$a_81_2 = {40 53 4a 5c 5b 41 50 47 51 5a 58 54 5c 5b 4a 55 46 5f 55 53 45 5f 44 45 53 5f 4b 45 59 5f 4f 55 46 5f 53 4d 41 52 54 43 41 52 44 5f 52 45 51 61 52 6b 5c 4d 5f 5f 63 5b } //02 00  @SJ\[APGQZXT\[JUF_USE_DES_KEY_OUF_SMARTCARD_REQaRk\M__c[
		$a_81_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 61 6c 63 2e 65 78 65 } //00 00  C:\Users\Public\calc.exe
	condition:
		any of ($a_*)
 
}