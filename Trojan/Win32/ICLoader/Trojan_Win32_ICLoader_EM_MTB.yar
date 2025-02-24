
rule Trojan_Win32_ICLoader_EM_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 61 71 72 73 76 74 74 2e 31 2e 31 32 32 36 34 } //1 .aqrsvtt.1.12264
		$a_81_1 = {57 4e 65 74 47 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 57 } //1 WNetGetConnectionW
		$a_81_2 = {42 72 69 6e 67 57 69 6e 64 6f 77 54 6f 54 6f 70 } //1 BringWindowToTop
		$a_81_3 = {43 73 72 43 6c 69 65 6e 74 43 61 6c 6c 53 65 72 76 65 72 } //1 CsrClientCallServer
		$a_81_4 = {61 6c 69 7a 65 54 68 75 6e 6b } //1 alizeThunk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_ICLoader_EM_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_81_0 = {5f 72 73 74 65 66 67 68 5f 36 5f 31 31 32 32 31 5f } //5 _rstefgh_6_11221_
		$a_81_1 = {5f 71 72 73 61 62 63 64 5f 33 5f 31 31 32 30 31 5f } //5 _qrsabcd_3_11201_
		$a_81_2 = {5f 71 72 73 61 62 63 64 5f 32 5f 31 31 32 30 32 5f } //5 _qrsabcd_2_11202_
		$a_81_3 = {41 6c 70 68 61 42 6c 65 6e 64 } //1 AlphaBlend
		$a_81_4 = {43 73 72 4e 65 77 54 68 72 65 61 64 } //1 CsrNewThread
		$a_81_5 = {4e 74 41 63 63 65 73 73 43 68 65 63 6b 42 79 54 79 70 65 52 65 73 75 6c 74 4c 69 73 74 41 6e 64 41 75 64 69 74 41 6c 61 72 6d } //1 NtAccessCheckByTypeResultListAndAuditAlarm
		$a_81_6 = {43 73 72 43 6c 69 65 6e 74 43 61 6c 6c 53 65 72 76 65 72 } //1 CsrClientCallServer
		$a_81_7 = {44 62 67 50 72 6f 6d 70 74 } //1 DbgPrompt
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=10
 
}