
rule VirTool_Win64_Ligelesz_B_MTB{
	meta:
		description = "VirTool:Win64/Ligelesz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {29 2e 52 65 6d 6f 74 65 41 64 64 72 } //1 ).RemoteAddr
		$a_81_1 = {6d 61 78 50 61 79 6c 6f 61 64 53 69 7a 65 46 6f 72 57 72 69 74 65 } //1 maxPayloadSizeForWrite
		$a_81_2 = {4c 69 73 74 65 6e 41 6e 64 53 65 72 76 65 } //1 ListenAndServe
		$a_81_3 = {53 65 74 53 65 73 73 69 6f 6e 54 69 63 6b 65 74 } //1 SetSessionTicket
		$a_81_4 = {2e 53 74 61 72 74 4c 69 67 6f 6c 6f } //1 .StartLigolo
		$a_81_5 = {2e 76 65 72 69 66 79 54 6c 73 43 65 72 74 69 66 69 63 61 74 65 } //1 .verifyTlsCertificate
		$a_81_6 = {2e 73 74 61 72 74 53 6f 63 6b 73 50 72 6f 78 79 } //1 .startSocksProxy
		$a_81_7 = {2e 68 61 6e 64 6c 65 52 65 6c 61 79 } //1 .handleRelay
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}