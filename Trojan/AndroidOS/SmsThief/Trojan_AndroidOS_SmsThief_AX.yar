
rule Trojan_AndroidOS_SmsThief_AX{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AX,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 69 6d 6d 79 73 65 72 76 2e 6f 6e 6c 69 6e 65 2f 77 65 62 2d 61 64 6d 69 6e 2f } //02 00  jimmyserv.online/web-admin/
		$a_01_1 = {61 70 69 2f 63 6f 6d 62 6f 2f 70 72 6f 66 69 6c 65 } //02 00  api/combo/profile
		$a_01_2 = {50 72 6f 66 69 6c 65 43 61 73 65 41 70 69 } //00 00  ProfileCaseApi
	condition:
		any of ($a_*)
 
}