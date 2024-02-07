
rule TrojanSpy_BAT_Keylog_AB{
	meta:
		description = "TrojanSpy:BAT/Keylog.AB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 70 00 68 00 70 00 } //01 00  /config.php
		$a_00_1 = {2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 } //01 00  /upload.php
		$a_01_2 = {2e 00 74 00 6d 00 70 00 } //01 00  .tmp
		$a_00_3 = {69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 70 00 65 00 67 00 } //01 00  image/jpeg
		$a_01_4 = {53 65 6e 64 53 63 72 65 65 6e } //01 00  SendScreen
		$a_01_5 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //02 00  keybd_event
		$a_00_6 = {43 00 3a 00 5c 00 73 00 79 00 73 00 74 00 6d 00 70 00 2e 00 74 00 6d 00 70 00 } //00 00  C:\systmp.tmp
		$a_00_7 = {5d 04 00 00 68 0f } //03 80 
	condition:
		any of ($a_*)
 
}