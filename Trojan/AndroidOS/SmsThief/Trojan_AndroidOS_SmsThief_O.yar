
rule Trojan_AndroidOS_SmsThief_O{
	meta:
		description = "Trojan:AndroidOS/SmsThief.O,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 67 61 70 6b 73 2e 6f 6e 6c 69 6e 65 2f 6b 6c 65 61 6e 68 6f 75 7a 5f 38 38 38 61 } //02 00  /gapks.online/kleanhouz_888a
		$a_00_1 = {3f 70 61 73 73 3d 61 70 70 31 36 38 26 63 6d 64 3d 73 6d 73 26 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //02 00  ?pass=app168&cmd=sms&sid=%1$s&sms=%2$s
		$a_00_2 = {61 6e 64 72 6f 69 64 5f 61 73 73 65 74 2f 46 50 58 2e 68 74 6d 6c } //00 00  android_asset/FPX.html
	condition:
		any of ($a_*)
 
}