
rule Trojan_AndroidOS_Smsthief_P{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 70 70 43 6f 6d 6d 6f 6e 2e 6f 72 67 } //01 00  com.appCommon.org
		$a_01_1 = {49 2c 68 61 76 65 20 46 75 63 6b 69 6e 67 20 59 6f 75 72 20 } //00 00  I,have Fucking Your 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Smsthief_P_2{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 73 50 68 6f 6e 65 4d 6f 76 65 20 74 65 6c 3a 2a 2a 32 31 2a 31 32 31 25 32 33 } //01 00  isPhoneMove tel:**21*121%23
		$a_01_1 = {73 6d 73 20 63 6c 69 65 6e 74 20 68 61 64 20 63 68 61 6e 67 65 64 } //00 00  sms client had changed
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Smsthief_P_3{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 79 61 70 70 6c 69 63 61 74 69 6f 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 41 6c 69 61 73 } //02 00  myapplicatior/MainActivityAlias
		$a_01_1 = {72 65 70 5f 6d 73 67 62 6f 64 79 33 } //02 00  rep_msgbody3
		$a_01_2 = {26 74 65 78 74 3d 2a 41 70 6c 69 6b 61 73 69 20 54 65 72 69 6e 73 74 61 6c 6c 20 64 69 20 50 65 72 61 6e 67 6b 61 74 20 3a 2a 20 5f } //00 00  &text=*Aplikasi Terinstall di Perangkat :* _
	condition:
		any of ($a_*)
 
}