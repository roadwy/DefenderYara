
rule Trojan_AndroidOS_Iconosys_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Iconosys.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 63 69 6e 63 6f 64 65 6d 61 79 6f 2f 62 75 7a 7a 65 72 2f 69 63 6f 6e 6f 73 79 73 2f 43 68 72 69 73 74 6d 61 73 54 69 6d 65 72 } //1 Lcincodemayo/buzzer/iconosys/ChristmasTimer
		$a_01_1 = {63 68 69 72 69 73 74 6d 61 73 63 6f 75 6e 74 31 31 } //1 chiristmascount11
		$a_01_2 = {6e 65 77 79 65 61 72 62 75 7a 7a 65 72 73 74 61 74 65 73 } //1 newyearbuzzerstates
		$a_01_3 = {74 72 69 63 6b 74 72 61 63 6b 65 72 73 74 61 74 65 73 } //2 tricktrackerstates
		$a_01_4 = {64 72 69 76 65 72 65 70 6c 61 79 73 74 61 74 65 73 } //2 drivereplaystates
		$a_01_5 = {73 61 6e 74 61 5f 62 75 74 74 6f 6e 73 5f 70 72 65 73 73 65 64 } //2 santa_buttons_pressed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=6
 
}