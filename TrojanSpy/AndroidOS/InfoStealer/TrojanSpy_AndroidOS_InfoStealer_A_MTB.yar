
rule TrojanSpy_AndroidOS_InfoStealer_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 4d 65 73 73 61 67 65 42 79 5f 43 4d 44 5f 54 52 4f 4a 41 4e 5f 43 4f 4e 4e 45 43 54 } //3 sendMessageBy_CMD_TROJAN_CONNECT
		$a_00_1 = {43 4d 44 5f 54 52 4f 4a 41 4e 5f 49 4e 46 4f } //1 CMD_TROJAN_INFO
		$a_00_2 = {67 65 74 43 61 6c 6c 52 65 63 6f 72 64 } //1 getCallRecord
		$a_00_3 = {67 65 74 42 72 6f 77 73 65 72 44 61 74 61 } //1 getBrowserData
		$a_00_4 = {63 68 6d 6f 64 20 37 37 37 20 2d 52 20 5c 64 61 74 61 5c 64 61 74 61 } //1 chmod 777 -R \data\data
		$a_00_5 = {73 63 72 65 65 6e 63 61 70 20 2d 70 } //1 screencap -p
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}