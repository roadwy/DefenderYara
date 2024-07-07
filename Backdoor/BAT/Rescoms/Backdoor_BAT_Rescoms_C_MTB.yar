
rule Backdoor_BAT_Rescoms_C_MTB{
	meta:
		description = "Backdoor:BAT/Rescoms.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_02_0 = {08 13 0d 11 0c 13 0e 11 0d 11 0e 11 0d 11 0e 6f 90 01 01 00 00 0a 08 11 0c 17 59 6f 90 01 01 00 00 0a 58 6f 90 01 01 00 00 0a 00 00 11 0c 17 58 13 0c 11 0c 08 6f 90 01 01 00 00 0a fe 04 13 0f 11 0f 2d c3 90 00 } //10
		$a_80_1 = {43 79 6f 74 65 6b } //Cyotek  3
		$a_80_2 = {74 78 74 62 78 74 61 62 } //txtbxtab  3
		$a_80_3 = {54 65 78 74 42 6f 78 54 61 62 53 74 6f 70 73 } //TextBoxTabStops  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}