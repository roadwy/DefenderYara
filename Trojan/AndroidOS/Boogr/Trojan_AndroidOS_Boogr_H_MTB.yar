
rule Trojan_AndroidOS_Boogr_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Boogr.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f 70 72 6f 6a 65 63 74 2f 90 02 16 4d 79 4e 6f 74 69 66 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 90 00 } //01 00 
		$a_01_1 = {52 45 41 44 5f 50 48 4f 4e 45 5f 4e 55 4d 42 45 52 53 } //01 00  READ_PHONE_NUMBERS
		$a_01_2 = {2f 61 70 69 2f 63 61 6c 6c 6c 6f 67 2f 62 6f 74 2f } //01 00  /api/calllog/bot/
		$a_01_3 = {77 70 61 5f 73 75 70 70 6c 69 63 61 6e 74 2e 63 6f 6e 66 } //01 00  wpa_supplicant.conf
		$a_01_4 = {2f 61 70 69 2f 63 6f 6e 74 61 63 74 2f 62 6f 74 2f } //01 00  /api/contact/bot/
		$a_01_5 = {67 6f 6f 73 2e 70 77 } //00 00  goos.pw
	condition:
		any of ($a_*)
 
}