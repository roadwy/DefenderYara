
rule TrojanSpy_AndroidOS_SAgnt_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 79 61 70 70 2f 72 61 74 6a 73 2f 54 6f 6f 6c 73 } //10 Lcom/myapp/ratjs/Tools
		$a_00_1 = {73 65 6e 64 4c 6f 63 61 74 69 6f 6e 2f } //1 sendLocation/
		$a_00_2 = {73 65 6e 64 63 61 6c 6c 6c 6f 67 } //1 sendcalllog
		$a_00_3 = {73 65 6e 64 61 6c 6c 73 6d 73 } //1 sendallsms
		$a_00_4 = {73 65 6e 64 41 70 70 73 } //1 sendApps
		$a_00_5 = {73 65 6e 64 44 65 76 69 63 65 4e 61 6d 65 } //1 sendDeviceName
		$a_00_6 = {73 65 6e 64 43 6f 6e 74 61 63 74 } //1 sendContact
		$a_00_7 = {53 4d 53 5f 53 45 4e 54 } //1 SMS_SENT
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=15
 
}