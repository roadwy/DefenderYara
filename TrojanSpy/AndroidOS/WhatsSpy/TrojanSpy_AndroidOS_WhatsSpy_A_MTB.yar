
rule TrojanSpy_AndroidOS_WhatsSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/WhatsSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 57 53 20 53 65 6e 74 2f 73 65 6e 74 5f } //1 /WS Sent/sent_
		$a_00_1 = {2f 57 53 20 52 65 63 69 62 65 64 2f } //1 /WS Recibed/
		$a_00_2 = {2f 57 53 20 50 72 69 76 61 74 65 2f } //1 /WS Private/
		$a_00_3 = {53 65 6e 64 5f 57 53 52 65 63 69 62 65 64 } //1 Send_WSRecibed
		$a_00_4 = {53 65 6e 64 5f 57 53 73 65 6e 64 } //1 Send_WSsend
		$a_00_5 = {6d 79 47 61 6c 6c 65 72 79 73 57 53 2e 6a 73 6f 6e } //1 myGallerysWS.json
		$a_00_6 = {6d 79 47 61 6c 6c 65 72 79 73 57 53 53 65 6e 64 2e 6a 73 6f 6e } //1 myGallerysWSSend.json
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}