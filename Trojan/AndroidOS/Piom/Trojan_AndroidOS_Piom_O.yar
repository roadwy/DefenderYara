
rule Trojan_AndroidOS_Piom_O{
	meta:
		description = "Trojan:AndroidOS/Piom.O,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 65 73 75 6c 74 65 6e 64 3d 6f 6b 26 61 63 74 69 6f 6e 3d 66 69 72 73 74 69 6e 73 74 61 6c 6c 26 61 6e 64 72 6f 69 64 69 64 3d } //2 resultend=ok&action=firstinstall&androidid=
		$a_01_1 = {73 65 74 74 69 6e 67 73 20 70 75 74 20 67 6c 6f 62 61 6c 20 73 6d 73 5f 6f 75 74 67 6f 69 6e 67 5f 63 68 65 63 6b 5f 69 6e 74 65 72 76 61 6c 5f 6d 73 20 31 30 30 30 } //2 settings put global sms_outgoing_check_interval_ms 1000
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}