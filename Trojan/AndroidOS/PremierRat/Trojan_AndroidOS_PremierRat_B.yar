
rule Trojan_AndroidOS_PremierRat_B{
	meta:
		description = "Trojan:AndroidOS/PremierRat.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 2e 6f 73 2e 6c 4f 43 4b 5f 4f 50 45 4e 45 44 } //01 00  android.os.lOCK_OPENED
		$a_00_1 = {41 6c 61 72 6d 52 65 63 52 65 61 64 53 6d 73 } //01 00  AlarmRecReadSms
		$a_00_2 = {61 6e 64 72 6f 69 64 2e 6f 73 2e 52 65 61 64 53 6d 73 65 73 } //00 00  android.os.ReadSmses
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}