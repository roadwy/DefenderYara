
rule Trojan_BAT_NjRat_NECY_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 2d 00 00 01 25 d0 5c 03 00 04 28 5c 00 00 0a 6f 86 00 00 0a 06 07 6f 8a 00 00 0a 17 } //10
		$a_01_1 = {71 33 6f 4d 56 65 35 34 77 45 34 37 77 34 76 36 38 43 37 73 32 49 } //2 q3oMVe54wE47w4v68C7s2I
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //2 WriteProcessMemory
		$a_01_3 = {49 6e 76 6f 6b 65 } //2 Invoke
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}