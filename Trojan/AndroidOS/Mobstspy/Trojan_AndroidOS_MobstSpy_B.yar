
rule Trojan_AndroidOS_MobstSpy_B{
	meta:
		description = "Trojan:AndroidOS/MobstSpy.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 63 2e 70 70 61 74 72 61 74 73 69 62 6f 6d 2e 77 77 77 2f 2f 3a 70 74 74 68 } //2 moc.ppatratsibom.www//:ptth
		$a_01_1 = {2f 67 63 6d 5f 73 65 72 76 65 72 5f 70 68 70 2f 68 61 70 70 79 5f 62 69 72 64 2f } //2 /gcm_server_php/happy_bird/
		$a_01_2 = {69 73 4e 6f 74 69 66 43 6c 65 61 72 } //2 isNotifClear
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}