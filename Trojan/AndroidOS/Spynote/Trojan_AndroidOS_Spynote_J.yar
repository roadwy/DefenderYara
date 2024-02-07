
rule Trojan_AndroidOS_Spynote_J{
	meta:
		description = "Trojan:AndroidOS/Spynote.J,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 65 78 69 74 2f 63 68 61 74 2f } //02 00  /exit/chat/
		$a_00_1 = {62 30 66 61 6c 73 65 } //01 00  b0false
		$a_00_2 = {4f 70 57 69 6e } //01 00  OpWin
		$a_00_3 = {6e 75 6c 6c 20 26 20 6e 75 6c 6c } //01 00  null & null
		$a_00_4 = {50 41 4e 47 20 21 21 } //00 00  PANG !!
	condition:
		any of ($a_*)
 
}