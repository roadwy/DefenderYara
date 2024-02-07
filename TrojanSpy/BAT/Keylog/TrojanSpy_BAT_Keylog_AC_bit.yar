
rule TrojanSpy_BAT_Keylog_AC_bit{
	meta:
		description = "TrojanSpy:BAT/Keylog.AC!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 6c 66 4d 65 6c 74 00 72 63 34 } //01 00  慈晬敍瑬爀㑣
		$a_01_1 = {6e 6f 6e 75 62 00 4d 65 6c 74 } //01 00  潮畮b敍瑬
		$a_01_2 = {47 65 74 53 74 65 61 6d 55 73 65 72 6e 61 6d 65 00 41 64 64 53 74 61 72 74 75 70 } //01 00 
		$a_01_3 = {4d 61 69 6e 4c 6f 6f 70 00 43 6f 6e 6e 65 63 74 00 50 72 6f 63 65 73 73 43 6f 6d 6d 61 6e 64 73 } //01 00  慍湩潌灯䌀湯敮瑣倀潲散獳潃浭湡獤
		$a_01_4 = {73 68 69 66 74 61 6e 64 63 61 70 73 } //00 00  shiftandcaps
	condition:
		any of ($a_*)
 
}