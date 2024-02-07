
rule Trojan_AndroidOS_Fakespy_A{
	meta:
		description = "Trojan:AndroidOS/Fakespy.A,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {34 35 30 30 36 } //02 00  45006
		$a_00_1 = {2f 73 65 72 76 6c 65 74 2f 55 70 6c 6f 61 64 4c 6f 67 } //02 00  /servlet/UploadLog
		$a_00_2 = {2f 73 65 72 76 6c 65 74 2f 43 6f 6e 74 61 63 74 73 55 70 6c 6f 61 64 } //02 00  /servlet/ContactsUpload
		$a_00_3 = {73 68 69 74 3a } //02 00  shit:
		$a_00_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 61 67 61 77 61 2d 65 78 70 2e 63 6f 2e 6a 70 2f } //00 00  http://www.sagawa-exp.co.jp/
		$a_00_5 = {5d 04 00 00 } //27 cb 
	condition:
		any of ($a_*)
 
}