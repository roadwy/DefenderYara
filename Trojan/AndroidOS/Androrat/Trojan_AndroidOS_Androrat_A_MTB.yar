
rule Trojan_AndroidOS_Androrat_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Androrat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 73 57 61 74 63 68 2e 64 62 } //01 00  smsWatch.db
		$a_00_1 = {4c 75 74 69 6c 73 2f 50 68 6f 6e 65 4d 6f 6e 69 74 6f 72 3b } //01 00  Lutils/PhoneMonitor;
		$a_00_2 = {53 54 4f 50 5f 4d 4f 4e 49 54 4f 52 5f 53 4d 53 } //01 00  STOP_MONITOR_SMS
		$a_00_3 = {64 65 6c 65 74 65 20 66 72 6f 6d 20 74 5f 73 6d 73 20 77 68 65 72 65 20 69 64 3d 3f } //01 00  delete from t_sms where id=?
		$a_00_4 = {68 69 64 65 49 6e 73 74 61 6c 6c } //00 00  hideInstall
		$a_00_5 = {5d 04 00 } //00 16 
	condition:
		any of ($a_*)
 
}