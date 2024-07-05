
rule Trojan_AndroidOS_Smsthief_D{
	meta:
		description = "Trojan:AndroidOS/Smsthief.D,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 75 6e 74 20 33 30 25 3a 20 28 69 6c 6f 76 65 72 65 64 39 39 29 20 52 4d } //01 00  Discount 30%: (ilovered99) RM
		$a_01_1 = {3f 70 61 73 73 3d 61 70 70 31 36 38 26 63 6d 64 3d 73 6d 73 26 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //00 00  ?pass=app168&cmd=sms&sid=%1$s&sms=%2$s
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Smsthief_D_2{
	meta:
		description = "Trojan:AndroidOS/Smsthief.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {62 74 6e 62 65 66 6f 72 70 61 79 } //02 00  btnbeforpay
		$a_01_1 = {63 6f 6d 2e 7a 65 72 6f 6f 6e 65 2e 64 69 76 61 72 61 6f 70 2e 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 41 6c 69 61 73 } //02 00  com.zeroone.divaraop.SplashActivityAlias
		$a_01_2 = {69 72 64 76 73 76 65 73 2e 63 66 2f 72 65 73 70 6f 6e 2e 70 68 70 } //00 00  irdvsves.cf/respon.php
	condition:
		any of ($a_*)
 
}