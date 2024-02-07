
rule Trojan_AndroidOS_Smsthief_P{
	meta:
		description = "Trojan:AndroidOS/Smsthief.P,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 79 61 70 70 6c 69 63 61 74 69 6f 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 41 6c 69 61 73 } //02 00  myapplicatior/MainActivityAlias
		$a_01_1 = {72 65 70 5f 6d 73 67 62 6f 64 79 33 } //02 00  rep_msgbody3
		$a_01_2 = {26 74 65 78 74 3d 2a 41 70 6c 69 6b 61 73 69 20 54 65 72 69 6e 73 74 61 6c 6c 20 64 69 20 50 65 72 61 6e 67 6b 61 74 20 3a 2a 20 5f } //00 00  &text=*Aplikasi Terinstall di Perangkat :* _
	condition:
		any of ($a_*)
 
}