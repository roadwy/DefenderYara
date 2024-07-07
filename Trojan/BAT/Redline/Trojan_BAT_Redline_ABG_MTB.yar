
rule Trojan_BAT_Redline_ABG_MTB{
	meta:
		description = "Trojan:BAT/Redline.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 ff a2 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c5 00 00 00 89 00 00 00 45 01 00 00 8e 04 00 00 ae 02 } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //1 get_IsAttached
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 55 70 64 61 74 65 } //1 DownloadAndExecuteUpdate
		$a_01_4 = {46 75 6c 6c 49 6e 66 6f 53 65 6e 64 65 72 } //1 FullInfoSender
		$a_01_5 = {47 61 6d 65 4c 61 75 6e 63 68 65 72 } //1 GameLauncher
		$a_01_6 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //1 GetAllNetworkInterfaces
		$a_01_7 = {47 65 74 42 72 6f 77 73 65 72 73 } //1 GetBrowsers
		$a_01_8 = {47 65 74 44 65 66 61 75 6c 74 49 50 76 34 41 64 64 72 65 73 73 } //1 GetDefaultIPv4Address
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=13
 
}