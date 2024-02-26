
rule Trojan_AndroidOS_BrowBot_A{
	meta:
		description = "Trojan:AndroidOS/BrowBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 64 61 74 61 5f 31 33 2f 69 6e 73 74 61 6c 6c 5f 31 33 2e 70 68 70 } //02 00  /data_13/install_13.php
		$a_01_1 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f 31 33 } //02 00  senderphone_13
		$a_01_2 = {53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 5f 31 33 } //00 00  SmsReceiverActivity_13
	condition:
		any of ($a_*)
 
}