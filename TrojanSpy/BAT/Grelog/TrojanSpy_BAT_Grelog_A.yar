
rule TrojanSpy_BAT_Grelog_A{
	meta:
		description = "TrojanSpy:BAT/Grelog.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 57 00 65 00 62 00 } //01 00  Stealer Web
		$a_01_1 = {47 00 72 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  GreyLogger
		$a_01_2 = {2f 00 72 00 65 00 6d 00 6f 00 74 00 65 00 5f 00 64 00 6c 00 2e 00 70 00 68 00 70 00 } //01 00  /remote_dl.php
		$a_01_3 = {2f 00 72 00 65 00 6d 00 6f 00 74 00 65 00 5f 00 64 00 6c 00 75 00 72 00 6c 00 2e 00 70 00 68 00 70 00 } //01 00  /remote_dlurl.php
		$a_01_4 = {2f 00 72 00 65 00 6d 00 6f 00 74 00 65 00 5f 00 62 00 6c 00 61 00 63 00 6b 00 6c 00 69 00 73 00 74 00 2e 00 70 00 68 00 70 00 } //01 00  /remote_blacklist.php
		$a_01_5 = {41 00 6e 00 6b 00 61 00 6d 00 61 00 20 00 53 00 68 00 69 00 65 00 6c 00 64 00 } //01 00  Ankama Shield
		$a_01_6 = {4b 65 79 4c 6f 67 } //00 00  KeyLog
		$a_01_7 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}