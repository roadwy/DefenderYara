
rule Trojan_AndroidOS_SAgnt_F_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 69 6d 70 6c 65 6d 6f 62 69 6c 65 74 6f 6f 6c 73 2f 74 65 70 6c 6f 61 70 70 } //01 00  com/simplemobiletools/teploapp
		$a_01_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 2f 73 65 6e 74 } //01 00  content://sms/sent
		$a_01_2 = {72 61 72 65 6d 65 64 69 75 6d 77 65 6c 6c 64 6f 6e 65 2e 63 6f 6d 2f 63 6c 69 63 6b 2e 70 68 70 } //01 00  raremediumwelldone.com/click.php
		$a_01_3 = {63 6f 72 72 65 6c 2e 73 70 61 63 65 2f 75 74 2e 70 68 70 } //01 00  correl.space/ut.php
		$a_01_4 = {73 65 74 4d 6f 62 69 6c 65 44 61 74 61 45 6e 61 62 6c 65 64 } //01 00  setMobileDataEnabled
		$a_01_5 = {67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //01 00  getPhoneNumber
		$a_01_6 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //00 00  /system/app/Superuser.apk
	condition:
		any of ($a_*)
 
}