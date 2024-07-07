
rule Trojan_BAT_Stealer_F_MTB{
	meta:
		description = "Trojan:BAT/Stealer.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 53 4f 44 49 48 46 49 53 4a 48 44 46 49 4b 53 4a 44 48 49 46 } //1 ASODIHFISJHDFIKSJDHIF
		$a_01_1 = {6c 6f 61 64 61 73 64 66 61 73 64 61 64 73 67 6f 6f 67 6c 65 } //1 loadasdfasdadsgoogle
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {73 61 66 64 73 63 76 7a 78 63 76 } //1 safdscvzxcv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}