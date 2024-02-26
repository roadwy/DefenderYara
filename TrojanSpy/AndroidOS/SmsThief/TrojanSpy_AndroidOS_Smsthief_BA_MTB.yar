
rule TrojanSpy_AndroidOS_Smsthief_BA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Smsthief.BA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 4d 65 73 73 61 67 65 3f 70 61 72 73 65 5f 6d 6f 64 65 3d 6d 61 72 6b 64 6f 77 6e 26 63 68 61 74 5f 69 64 3d } //01 00  sendMessage?parse_mode=markdown&chat_id=
		$a_01_1 = {52 65 63 65 69 76 65 53 6d 73 } //01 00  ReceiveSms
		$a_01_2 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 70 70 6a 61 76 61 } //01 00  com/example/appjava
		$a_01_3 = {73 6d 73 4d 65 73 73 61 67 65 41 72 72 } //00 00  smsMessageArr
	condition:
		any of ($a_*)
 
}