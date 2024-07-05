
rule Trojan_AndroidOS_SmsAgent_AW{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.AW,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 6f 72 77 61 72 64 54 61 73 6b 46 6f 72 54 65 6c 65 67 72 61 6d } //02 00  ForwardTaskForTelegram
		$a_01_1 = {66 6f 72 77 61 72 64 56 69 61 53 4d 53 } //02 00  forwardViaSMS
		$a_01_2 = {43 4f 55 52 49 45 52 41 44 46 59 46 45 53 47 37 56 49 46 58 41 44 4d 49 4e 31 30 2f 72 65 63 69 65 76 65 72 2e 70 68 70 } //00 00  COURIERADFYFESG7VIFXADMIN10/reciever.php
	condition:
		any of ($a_*)
 
}