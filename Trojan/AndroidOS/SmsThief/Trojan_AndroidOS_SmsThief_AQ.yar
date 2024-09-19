
rule Trojan_AndroidOS_SmsThief_AQ{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AQ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6e 2f 62 61 6c 61 6a 69 2f 4d 79 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //2 in/balaji/MyBroadcastReceiver
		$a_01_1 = {62 61 6c 61 6a 69 2f 4d 79 46 6f 72 65 67 72 6f 75 6e 64 53 65 72 76 69 63 65 } //2 balaji/MyForegroundService
		$a_01_2 = {67 61 6e 65 73 68 61 63 61 72 72 65 6e 74 61 6c 73 2e 63 6f 6d 2f 6f 6c 64 2d 6d 65 73 73 61 67 65 73 2e 70 68 70 2f } //2 ganeshacarrentals.com/old-messages.php/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}