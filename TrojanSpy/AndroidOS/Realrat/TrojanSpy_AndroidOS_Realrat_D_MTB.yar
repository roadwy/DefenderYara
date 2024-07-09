
rule TrojanSpy_AndroidOS_Realrat_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Realrat.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_03_0 = {2f 52 65 6d 6f 74 65 [0-20] 2f 72 65 71 2e 70 68 70 } //1
		$a_00_1 = {2f 73 65 6e 64 5f 73 6d 73 } //1 /send_sms
		$a_00_2 = {2f 68 69 64 65 } //1 /hide
		$a_00_3 = {2f 73 65 6e 64 5f 6c 61 73 74 5f 73 6d 73 } //1 /send_last_sms
		$a_00_4 = {5f 73 6d 73 67 69 72 5f 6d 65 73 73 61 67 65 72 65 63 65 69 76 65 64 } //1 _smsgir_messagereceived
		$a_00_5 = {69 6e 73 74 61 6c 6c 2e 74 78 74 } //1 install.txt
		$a_00_6 = {6d 73 67 69 64 2e 74 78 74 } //1 msgid.txt
		$a_00_7 = {4c 63 6f 6d 2f 72 65 7a 61 2f 73 68 2f 64 65 76 69 63 65 69 6e 66 6f 2f 44 69 76 69 63 65 49 6e 66 6f } //1 Lcom/reza/sh/deviceinfo/DiviceInfo
		$a_00_8 = {74 65 6f 64 6f 72 2e 69 72 6f 6d 69 7a 62 61 6e 2e 69 72 } //1 teodor.iromizban.ir
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=7
 
}