
rule Trojan_BAT_Remcos_GC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {43 6f 6e 73 6f 6c 65 41 70 70 [0-04] 2e 65 78 65 } //1
		$a_81_1 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //1 //cdn.discordapp.com/attachments/
		$a_81_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //1 WindowsFormsApp
		$a_81_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_6 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_7 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_8 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_BAT_Remcos_GC_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 41 64 64 49 6e 50 72 6f 63 65 73 73 33 32 2e 65 78 65 } //\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe  20
		$a_02_1 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-14] 2e 00 [0-1e] 2e 00 72 00 75 00 2f 00 [0-28] 90 0a 96 00 68 00 } //5
		$a_02_2 = {74 74 70 73 3a 2f 2f [0-14] 2e [0-1e] 2e 72 75 2f [0-28] 90 0a 96 00 68 } //5
		$a_02_3 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-1e] 2e 00 72 00 75 00 2f 00 [0-28] 90 0a 5a 00 68 00 } //5
		$a_02_4 = {74 74 70 73 3a 2f 2f [0-1e] 2e 72 75 2f [0-28] 90 0a 5a 00 68 } //5
		$a_80_5 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  1
		$a_80_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_7 = {73 65 74 5f 45 78 70 65 63 74 31 30 30 43 6f 6e 74 69 6e 75 65 } //set_Expect100Continue  1
		$a_80_8 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  1
	condition:
		((#a_80_0  & 1)*20+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_02_4  & 1)*5+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=27
 
}