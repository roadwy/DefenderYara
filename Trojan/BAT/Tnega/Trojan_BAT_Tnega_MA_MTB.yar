
rule Trojan_BAT_Tnega_MA_MTB{
	meta:
		description = "Trojan:BAT/Tnega.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {08 11 04 06 11 04 91 07 11 04 07 8e 69 5d 91 09 58 20 ff 00 00 00 5f 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 17 59 fe 02 16 fe 01 13 05 11 05 2d ce } //10
		$a_80_1 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //SecurityProtocolType  3
		$a_80_2 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //HttpWebResponse  3
		$a_80_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggerBrowsableAttribute  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}