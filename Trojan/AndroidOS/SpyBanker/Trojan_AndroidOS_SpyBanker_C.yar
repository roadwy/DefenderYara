
rule Trojan_AndroidOS_SpyBanker_C{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 73 61 76 65 5f 73 6d 73 2e 70 68 70 3f 70 68 6f 6e 65 3d } //2 000webhostapp.com/save_sms.php?phone=
		$a_01_1 = {52 45 51 5f 43 4f 44 45 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 53 45 4e 44 5f 53 4d 53 } //2 REQ_CODE_PERMISSION_SEND_SMS
		$a_01_2 = {6d 79 73 6d 73 6d 61 6e 61 67 65 72 } //2 mysmsmanager
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}