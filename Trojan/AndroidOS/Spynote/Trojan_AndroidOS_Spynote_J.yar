
rule Trojan_AndroidOS_Spynote_J{
	meta:
		description = "Trojan:AndroidOS/Spynote.J,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 65 78 69 74 2f 63 68 61 74 2f } //2 /exit/chat/
		$a_00_1 = {62 30 66 61 6c 73 65 } //2 b0false
		$a_00_2 = {4f 70 57 69 6e } //1 OpWin
		$a_00_3 = {6e 75 6c 6c 20 26 20 6e 75 6c 6c } //1 null & null
		$a_00_4 = {50 41 4e 47 20 21 21 } //1 PANG !!
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}