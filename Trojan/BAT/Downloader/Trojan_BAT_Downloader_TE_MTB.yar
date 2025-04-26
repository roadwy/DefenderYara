
rule Trojan_BAT_Downloader_TE_MTB{
	meta:
		description = "Trojan:BAT/Downloader.TE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 31 33 2e 32 31 32 2e 38 38 2e 36 30 3a 38 38 2f 6c 6f 67 } //1 http://113.212.88.60:88/log
		$a_81_1 = {68 74 74 70 3a 2f 2f 31 31 33 2e 32 31 32 2e 38 38 2e 36 30 2f 56 76 2f 72 65 73 6f 75 72 63 65 2e 6a 73 6f 6e } //1 http://113.212.88.60/Vv/resource.json
		$a_81_2 = {53 45 4c 45 43 54 20 75 73 65 72 6e 61 6d 65 20 46 52 4f 4d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //1 SELECT username FROM Win32_ComputerSystem
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_5 = {44 3a 5c 2e 30 30 30 2e 50 72 69 76 61 74 65 5c 30 30 30 2e 4e 45 54 5c 56 76 4d 61 69 6e 5c 71 30 5c 34 2e 30 5c 56 76 53 76 63 48 6f 73 74 5c 56 76 53 76 63 48 6f 73 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 2e 70 64 62 } //1 D:\.000.Private\000.NET\VvMain\q0\4.0\VvSvcHost\VvSvcHost\obj\Release\RuntimeBroker.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}