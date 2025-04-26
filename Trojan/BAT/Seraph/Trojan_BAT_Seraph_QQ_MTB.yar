
rule Trojan_BAT_Seraph_QQ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {16 0a 2b 0e 20 e7 03 00 00 28 29 00 00 0a 06 17 58 0a 06 1f 14 32 ed } //10
		$a_80_1 = {52 65 73 6f 75 72 63 65 48 61 63 6b 65 72 } //ResourceHacker  3
		$a_80_2 = {65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //eb tonnac margorp sihT!  3
		$a_80_3 = {6e 69 61 4d 6c 6c 44 72 6f 43 5f } //niaMllDroC_  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}