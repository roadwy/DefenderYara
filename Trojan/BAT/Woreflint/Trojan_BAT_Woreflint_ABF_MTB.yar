
rule Trojan_BAT_Woreflint_ABF_MTB{
	meta:
		description = "Trojan:BAT/Woreflint.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {16 0b 04 17 da 0c 16 0a 2b 0a 07 03 06 94 d6 0b 06 17 d6 0a 06 08 31 f2 07 6c 04 6c 5b 02 02 } //10
		$a_80_1 = {67 65 74 41 76 65 72 61 67 65 } //getAverage  3
		$a_80_2 = {6b 61 79 69 74 53 61 79 69 73 69 } //kayitSayisi  3
		$a_80_3 = {73 71 6c 43 61 6c 69 73 74 69 72 } //sqlCalistir  3
		$a_80_4 = {64 73 47 65 74 69 72 } //dsGetir  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}