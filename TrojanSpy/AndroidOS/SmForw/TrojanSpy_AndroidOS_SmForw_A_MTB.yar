
rule TrojanSpy_AndroidOS_SmForw_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 5f 70 68 6f 6e 6c 69 73 74 } //01 00  send_phonlist
		$a_00_1 = {62 61 6e 6b 2e 73 62 61 6e 6b 2e 61 63 74 69 76 69 74 79 } //01 00  bank.sbank.activity
		$a_00_2 = {2f 67 65 74 5f 73 6d 73 5f 63 6f 6d 6d 61 6e 64 } //01 00  /get_sms_command
		$a_00_3 = {68 61 6e 61 2e 61 70 6b } //01 00  hana.apk
		$a_00_4 = {77 65 62 63 61 73 68 2e 77 6f 6f 72 69 62 61 6e 6b } //00 00  webcash.wooribank
	condition:
		any of ($a_*)
 
}