
rule Trojan_Win64_IcedID_WD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.WD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 10 48 83 c0 04 83 e9 04 89 17 48 8d 7f 04 73 ef 83 c1 04 8a 10 74 10 } //10
		$a_80_1 = {61 6e 76 73 79 79 6a 73 6e 78 65 } //anvsyyjsnxe  3
		$a_80_2 = {69 78 74 64 66 72 70 64 63 76 } //ixtdfrpdcv  3
		$a_80_3 = {70 6e 70 77 65 75 67 69 69 62 74 65 78 64 71 } //pnpweugiibtexdq  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}