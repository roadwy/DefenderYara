
rule Trojan_BAT_Azorult_MA_MTB{
	meta:
		description = "Trojan:BAT/Azorult.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //01 00  DisableTaskMgr
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //01 00  DisableRealtimeMonitoring
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_3 = {67 00 6f 00 6a 00 65 00 6b 00 70 00 72 00 6f 00 6d 00 6f 00 2e 00 63 00 6f 00 6d 00 } //01 00  gojekpromo.com
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_5 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_6 = {52 65 67 69 73 74 72 79 4b 65 79 50 65 72 6d 69 73 73 69 6f 6e 43 68 65 63 6b } //01 00  RegistryKeyPermissionCheck
		$a_01_7 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}