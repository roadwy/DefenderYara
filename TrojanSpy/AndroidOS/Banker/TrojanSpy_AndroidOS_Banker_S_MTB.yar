
rule TrojanSpy_AndroidOS_Banker_S_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 73 43 61 6c 6c 4e 75 6d 62 65 72 54 6f 53 65 72 76 65 72 } //1 sendsCallNumberToServer
		$a_00_1 = {73 74 61 72 74 53 66 6f 72 53 65 6e 64 } //1 startSforSend
		$a_00_2 = {67 61 74 69 6e 67 2e 70 68 70 } //1 gating.php
		$a_00_3 = {73 65 6e 64 53 52 65 63 52 65 71 75 65 73 74 } //1 sendSRecRequest
		$a_00_4 = {6c 6b 72 69 73 68 74 69 66 61 61 2e 63 6f 6d } //1 lkrishtifaa.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}