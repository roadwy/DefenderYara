
rule Trojan_BAT_Seraph_AAUX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 06 11 00 94 11 06 11 02 94 58 20 00 01 00 00 5d 94 13 03 38 ?? ff ff ff 11 06 11 01 11 01 9e } //2
		$a_01_1 = {11 07 11 01 03 11 01 91 11 03 61 d2 9c } //2
		$a_01_2 = {47 00 71 00 71 00 63 00 64 00 77 00 63 00 64 00 62 00 67 00 6f 00 6c 00 76 00 6b 00 74 00 6e 00 66 00 64 00 6e 00 } //2 Gqqcdwcdbgolvktnfdn
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}