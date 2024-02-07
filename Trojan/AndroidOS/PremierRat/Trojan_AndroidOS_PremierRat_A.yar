
rule Trojan_AndroidOS_PremierRat_A{
	meta:
		description = "Trojan:AndroidOS/PremierRat.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 65 6e 64 43 61 70 74 75 72 65 53 63 72 65 65 6e 53 68 6f 74 2e 70 68 70 } //01 00  /sendCaptureScreenShot.php
		$a_00_1 = {2f 52 4d 50 61 6e 65 6c 2e 61 70 6b } //01 00  /RMPanel.apk
		$a_00_2 = {62 72 6f 61 64 63 61 73 74 5f 63 61 6c 6c 73 5f 68 69 73 74 72 6f 79 5f 6a 73 6f 6e } //00 00  broadcast_calls_histroy_json
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}