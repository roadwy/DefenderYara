
rule Trojan_AndroidOS_SmsThief_AY{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AY,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 6d 73 72 65 63 65 76 69 65 72 2f 73 74 61 72 74 75 70 4f 6e 42 6f 6f 74 55 70 52 65 63 65 69 76 65 72 } //02 00  smsrecevier/startupOnBootUpReceiver
		$a_01_1 = {61 70 70 6f 69 6e 74 6d 65 6e 74 73 65 72 76 69 63 65 30 2e 77 69 78 73 69 74 65 2e 63 6f 6d } //02 00  appointmentservice0.wixsite.com
		$a_01_2 = {63 6f 6d 70 6c 61 69 6e 66 31 33 2f 4d 79 5f 46 69 6c 65 2e 74 78 74 } //02 00  complainf13/My_File.txt
		$a_01_3 = {63 6f 2e 69 6e 2f 61 64 6d 69 6e 64 61 74 61 2e 74 78 74 } //00 00  co.in/admindata.txt
	condition:
		any of ($a_*)
 
}