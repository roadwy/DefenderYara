
rule Trojan_AndroidOS_FakeApp_J{
	meta:
		description = "Trojan:AndroidOS/FakeApp.J,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 74 4b 57 66 72 6f 6d 53 65 72 76 65 72 } //02 00  getKWfromServer
		$a_01_1 = {61 63 74 69 6f 6e 4c 6f 61 64 41 6f 63 } //02 00  actionLoadAoc
		$a_01_2 = {73 65 6e 64 4b 77 44 65 66 61 75 6c 74 } //00 00  sendKwDefault
	condition:
		any of ($a_*)
 
}