
rule Worm_BAT_Puontib_A{
	meta:
		description = "Worm:BAT/Puontib.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {38 30 01 00 00 11 04 11 05 9a 0b 00 07 6f ?? ?? ?? ?? 18 fe 01 16 fe 01 13 06 11 06 3a 0d 01 00 00 } //3
		$a_00_1 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_01_2 = {57 6f 52 6d 59 00 } //1 潗浒Y
		$a_01_3 = {69 6e 66 65 63 74 44 72 69 76 65 73 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}