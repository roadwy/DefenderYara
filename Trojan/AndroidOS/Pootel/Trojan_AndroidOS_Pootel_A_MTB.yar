
rule Trojan_AndroidOS_Pootel_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Pootel.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 6f 62 6f 6d 2f 73 75 62 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //02 00  modobom/sub/MainActivity
		$a_01_1 = {74 69 6b 69 74 61 6b 61 2f 73 75 62 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  tikitaka/sub/MainActivity
		$a_01_2 = {6d 6f 64 6f 62 6f 6d 2e 73 65 72 76 69 63 65 73 2f 61 70 69 } //01 00  modobom.services/api
		$a_01_3 = {2f 43 6f 6e 66 69 72 6d 53 6d 73 52 65 63 65 69 76 65 72 } //01 00  /ConfirmSmsReceiver
		$a_01_4 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //00 00  sendTextMessage
	condition:
		any of ($a_*)
 
}