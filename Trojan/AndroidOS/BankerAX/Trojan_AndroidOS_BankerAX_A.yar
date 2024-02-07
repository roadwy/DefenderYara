
rule Trojan_AndroidOS_BankerAX_A{
	meta:
		description = "Trojan:AndroidOS/BankerAX.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 6b 2e 61 78 69 73 62 61 6e 6b } //02 00  com.sk.axisbank
		$a_01_1 = {61 78 69 73 73 74 6f 72 65 2e 69 6e 2f 61 70 69 2f 70 6f 69 6e 74 73 2e 70 68 70 } //02 00  axisstore.in/api/points.php
		$a_01_2 = {4b 45 59 5f 45 54 55 53 45 52 4e 41 4d 45 } //02 00  KEY_ETUSERNAME
		$a_01_3 = {75 72 65 6d 69 61 } //00 00  uremia
	condition:
		any of ($a_*)
 
}