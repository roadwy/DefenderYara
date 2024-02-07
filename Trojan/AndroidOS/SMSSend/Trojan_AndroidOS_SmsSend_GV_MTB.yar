
rule Trojan_AndroidOS_SmsSend_GV_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSend.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 69 72 69 70 69 70 69 61 70 70 73 2f 64 65 6c 69 66 75 6e } //02 00  com/piripipiapps/delifun
		$a_01_1 = {74 72 61 63 6b 49 6e 66 6f } //01 00  trackInfo
		$a_01_2 = {53 4d 53 5f 53 45 4e 54 } //01 00  SMS_SENT
		$a_01_3 = {46 65 6c 69 63 69 74 61 63 69 6f 6e 65 73 21 20 41 63 74 69 76 61 73 74 65 20 65 6c 20 73 65 72 76 69 63 69 6f } //01 00  Felicitaciones! Activaste el servicio
		$a_01_4 = {68 74 74 70 3a 2f 2f 61 70 6b 2e 73 6f 75 6e 64 2e 63 6f 6d 2e 70 79 2f 74 72 61 63 6b 2e 70 68 70 } //00 00  http://apk.sound.com.py/track.php
	condition:
		any of ($a_*)
 
}