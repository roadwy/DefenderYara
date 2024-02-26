
rule TrojanSpy_AndroidOS_SMSThief_AY_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSThief.AY!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 53 4d 53 } //01 00  SendSMS
		$a_01_1 = {77 65 62 73 65 74 74 69 6e 67 6b 75 } //01 00  websettingku
		$a_01_2 = {52 65 63 65 69 76 65 53 6d 73 } //01 00  ReceiveSms
		$a_01_3 = {73 65 6e 64 4d 65 73 73 61 67 65 3f 70 61 72 73 65 5f 6d 6f 64 65 3d 6d 61 72 6b 64 6f 77 6e 26 63 68 61 74 5f 69 64 3d } //01 00  sendMessage?parse_mode=markdown&chat_id=
		$a_01_4 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 6d 79 61 70 70 6c 69 63 61 74 69 6f 6f } //00 00  com.example.myapplicatioo
	condition:
		any of ($a_*)
 
}