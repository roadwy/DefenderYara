
rule Trojan_AndroidOS_SmsThief_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 61 70 70 2f 68 6f 6d 65 63 6c 65 61 6e 69 6e 67 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  Lcom/app/homecleaning/MainActivity
		$a_00_1 = {61 70 69 5f 73 70 61 32 34 31 32 35 2f 61 70 69 5f 65 73 70 61 6e 6f 6c } //01 00  api_spa24125/api_espanol
		$a_00_2 = {2f 61 70 69 2e 70 68 70 3f 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //00 00  /api.php?sid=%1$s&sms=%2$s
	condition:
		any of ($a_*)
 
}