
rule Trojan_BAT_AgentTesla_NV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 11 0e 17 da 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 09 11 0e 09 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 06 da 13 0f 11 04 11 0f 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 13 04 11 0e 17 d6 13 0e 11 0e 11 0d 31 a5 90 00 } //1
		$a_01_1 = {86 06 45 00 86 06 45 00 86 06 45 00 86 06 45 00 86 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {47 4d 59 4e 41 4d 45 } //1 GMYNAME
		$a_81_1 = {44 65 73 74 72 6f 79 5f 45 76 65 72 79 74 68 69 6e 67 } //1 Destroy_Everything
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_3 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 56 65 72 73 69 6f 6e 69 6e 67 } //1 System.Runtime.Versioning
		$a_81_4 = {62 69 67 73 74 72 69 6e 67 } //1 bigstring
		$a_81_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_81_6 = {77 63 6c 69 65 6e 74 } //1 wclient
		$a_81_7 = {74 6f 74 61 6c 6c 69 73 74 } //1 totallist
		$a_81_8 = {4f 4e 45 5f 53 54 52 49 4e 47 45 6e 74 72 4f 4e 45 5f 53 54 52 49 4e 47 79 50 6f 69 6e 74 4f 4e 45 5f 53 54 52 49 4e 47 } //1 ONE_STRINGEntrONE_STRINGyPointONE_STRING
		$a_81_9 = {2e 6f 6e 6c 69 6e 65 2f 62 61 73 65 2f } //1 .online/base/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}