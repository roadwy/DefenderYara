
rule Trojan_Win32_SuspGolang_LK{
	meta:
		description = "Trojan:Win32/SuspGolang.LK,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {52 70 6f 72 74 46 77 64 53 74 6f 70 4c 69 73 74 65 6e 65 72 52 65 71 29 2e } //1 RportFwdStopListenerReq).
		$a_81_1 = {52 70 6f 72 74 46 77 64 53 74 61 72 74 4c 69 73 74 65 6e 65 72 52 65 71 29 2e } //1 RportFwdStartListenerReq).
		$a_81_2 = {52 70 6f 72 74 46 77 64 4c 69 73 74 65 6e 65 72 29 2e } //1 RportFwdListener).
		$a_81_3 = {52 70 6f 72 74 46 77 64 4c 69 73 74 65 6e 65 72 73 29 2e } //1 RportFwdListeners).
		$a_81_4 = {52 70 6f 72 74 46 77 64 4c 69 73 74 65 6e 65 72 73 52 65 71 29 2e } //1 RportFwdListenersReq).
		$a_81_5 = {52 50 6f 72 74 66 77 64 29 2e } //1 RPortfwd).
		$a_81_6 = {52 50 6f 72 74 66 77 64 52 65 71 29 2e } //1 RPortfwdReq).
		$a_81_7 = {43 68 6d 6f 64 52 65 71 29 2e } //1 ChmodReq).
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}