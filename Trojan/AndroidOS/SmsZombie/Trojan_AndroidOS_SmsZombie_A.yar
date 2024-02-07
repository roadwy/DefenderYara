
rule Trojan_AndroidOS_SmsZombie_A{
	meta:
		description = "Trojan:AndroidOS/SmsZombie.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 73 20 64 6f 20 43 6c 65 61 72 20 6c 6f 67 63 61 74 20 63 61 63 68 65 } //01 00  Has do Clear logcat cache
		$a_01_1 = {2f 70 68 6f 6e 65 2e 78 6d 6c } //01 00  /phone.xml
		$a_01_2 = {53 54 41 52 54 31 31 31 } //01 00  START111
		$a_01_3 = {41 6e 64 70 68 6f 6e 65 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //00 00  AndphoneActivity.java
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SmsZombie_A_2{
	meta:
		description = "Trojan:AndroidOS/SmsZombie.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 33 33 2e 6a 70 67 } //01 00  a33.jpg
		$a_01_1 = {62 61 6f 78 69 61 6e 5f 7a 68 75 73 68 6f 75 } //01 00  baoxian_zhushou
		$a_01_2 = {4e 65 74 77 6f 72 6b 50 49 4e } //01 00  NetworkPIN
		$a_01_3 = {64 61 74 61 2f 61 6e 64 72 6f 69 64 2e 70 68 6f 6e 65 2e 63 6f 6d 2f 66 69 6c 65 73 2f 70 68 6f 6e 65 2e 78 6d 6c } //00 00  data/android.phone.com/files/phone.xml
	condition:
		any of ($a_*)
 
}