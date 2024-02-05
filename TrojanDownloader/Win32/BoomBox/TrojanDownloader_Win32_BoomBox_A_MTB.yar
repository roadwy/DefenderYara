
rule TrojanDownloader_Win32_BoomBox_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/BoomBox.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 03 00 "
		
	strings :
		$a_80_0 = {42 4f 4f 4d } //BOOM  03 00 
		$a_80_1 = {69 73 5f 64 6f 77 6e 6c 6f 61 64 61 62 6c 65 } //is_downloadable  03 00 
		$a_80_2 = {42 65 61 72 65 72 } //Bearer  03 00 
		$a_80_3 = {47 65 74 49 50 47 6c 6f 62 61 6c 50 72 6f 70 65 72 74 69 65 73 } //GetIPGlobalProperties  03 00 
		$a_80_4 = {31 32 33 33 74 30 34 70 37 6a 6e 33 6e 34 72 67 } //1233t04p7jn3n4rg  03 00 
		$a_80_5 = {31 32 33 64 6f 33 79 34 72 33 37 38 6f 35 74 33 34 6f 6e 66 37 74 33 6f 35 37 33 74 66 6f 37 33 } //123do3y4r378o5t34onf7t3o573tfo73  03 00 
		$a_80_6 = {61 65 73 5f 63 72 79 70 74 } //aes_crypt  03 00 
		$a_80_7 = {2f 74 6d 70 2f 72 65 61 64 6d 65 2e 70 64 66 } ///tmp/readme.pdf  03 00 
		$a_80_8 = {5c 4e 61 74 69 76 65 43 61 63 68 65 53 76 63 2e 64 6c 6c 20 5f 63 6f 6e 66 69 67 4e 61 74 69 76 65 43 61 63 68 65 } //\NativeCacheSvc.dll _configNativeCache  03 00 
		$a_80_9 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  00 00 
	condition:
		any of ($a_*)
 
}