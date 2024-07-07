
rule Trojan_BAT_AgentTesla_ABN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 31 11 00 00 95 36 03 16 2b 01 17 17 59 7e 2f 00 00 04 1b 9a 20 76 10 00 00 95 5f 09 0a 7e 2f 00 00 04 1b 9a 20 d2 10 00 00 95 61 58 81 0a 00 00 01 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_BAT_AgentTesla_ABN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {0a 06 1f 10 8d 90 01 03 01 6f 90 01 03 0a 06 06 6f 90 01 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 0b 02 28 90 01 03 06 73 90 01 03 0a 0c 90 0a 3c 00 06 72 01 90 01 02 70 28 05 90 01 02 06 6f 05 90 00 } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {55 70 6c 6f 61 64 44 61 74 61 } //1 UploadData
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}