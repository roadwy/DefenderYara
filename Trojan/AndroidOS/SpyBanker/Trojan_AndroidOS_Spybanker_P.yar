
rule Trojan_AndroidOS_Spybanker_P{
	meta:
		description = "Trojan:AndroidOS/Spybanker.P,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 32 52 65 63 65 69 76 65 72 46 6f 72 4d 61 6e 69 66 65 73 74 } //2 Sms2ReceiverForManifest
		$a_01_1 = {42 61 63 6b 67 72 6f 75 6e 64 53 65 72 76 69 63 65 53 74 61 72 74 65 72 52 65 63 65 69 76 65 72 } //2 BackgroundServiceStarterReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}