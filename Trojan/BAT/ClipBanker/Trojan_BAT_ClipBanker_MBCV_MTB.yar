
rule Trojan_BAT_ClipBanker_MBCV_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MBCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 35 61 36 61 35 33 35 65 2d 39 36 37 35 2d 34 66 35 39 2d 62 63 39 31 2d 35 62 62 34 32 31 35 32 63 66 38 30 } //5 $5a6a535e-9675-4f59-bc91-5bb42152cf80
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}