
rule TrojanSpy_AndroidOS_SmsThief_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 69 72 2f 73 69 71 65 2f 68 6f 6c 6f 2f 63 6f 6e 6e 65 63 74 3b } //2 Lir/siqe/holo/connect;
		$a_00_1 = {4c 69 72 2f 73 69 71 65 2f 68 6f 6c 6f 2f 4d 79 52 65 63 65 69 76 65 72 3b } //2 Lir/siqe/holo/MyReceiver;
		$a_00_2 = {2e 70 68 70 3f 70 68 6f 6e 65 3d } //1 .php?phone=
		$a_00_3 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}
rule TrojanSpy_AndroidOS_SmsThief_M_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {4c 69 72 2f 70 61 72 64 61 6b 68 ?? 2f 53 6d 73 24 53 65 6e 64 50 6f 73 74 52 65 71 75 65 73 74 3b } //1
		$a_00_1 = {4c 61 64 72 74 2f 41 44 52 54 53 65 6e 64 65 72 3b } //1 Ladrt/ADRTSender;
		$a_00_2 = {53 6d 73 52 65 63 65 69 76 65 72 } //1 SmsReceiver
		$a_00_3 = {67 65 74 44 61 74 61 48 74 74 70 55 72 6c 43 6f 6e 6e 65 63 74 69 6f 6e } //1 getDataHttpUrlConnection
		$a_00_4 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}