
rule Trojan_Win64_Tedy_LMO_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 0a 00 00 "
		
	strings :
		$a_81_0 = {63 68 67 77 73 7a 75 6d 61 74 71 65 64 76 79 6b 6a 70 6e 62 72 78 } //1 chgwszumatqedvykjpnbrx
		$a_81_1 = {64 63 78 73 75 71 67 6a 61 72 6d 74 65 76 70 6e 7a 6b 66 77 68 62 } //2 dcxsuqgjarmtevpnzkfwhb
		$a_81_2 = {64 68 76 75 6b 6a 72 71 65 61 63 6d 79 70 62 6e 67 74 77 66 73 7a } //3 dhvukjrqeacmypbngtwfsz
		$a_81_3 = {64 6b 79 62 67 77 70 7a 76 73 6e 75 6d 78 68 72 74 61 66 71 6a 63 } //4 dkybgwpzvsnumxhrtafqjc
		$a_81_4 = {70 76 6b 73 67 78 74 7a 6e 75 72 63 62 61 68 65 6d 66 71 6a 77 79 } //5 pvksgxtznurcbahemfqjwy
		$a_81_5 = {74 76 64 67 63 70 73 6b 68 71 79 72 6d 65 7a 62 6a 6e 77 61 78 75 } //6 tvdgcpskhqyrmezbjnwaxu
		$a_81_6 = {76 6a 61 74 66 79 65 6b 77 67 6e 71 62 75 72 64 73 70 78 7a 68 6d } //7 vjatfyekwgnqburdspxzhm
		$a_81_7 = {77 7a 6b 62 71 78 67 65 70 79 72 68 74 63 76 6e 61 75 66 6d 6a 64 } //8 wzkbqxgepyrhtcvnaufmjd
		$a_81_8 = {79 6b 65 61 64 70 62 75 6e 72 78 63 7a 71 76 67 77 73 68 6a 6d 74 } //9 ykeadpbunrxczqvgwshjmt
		$a_81_9 = {79 77 74 64 73 6b 66 6e 71 61 78 65 72 67 75 6a 6d 70 76 63 62 68 } //10 ywtdskfnqaxergujmpvcbh
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8+(#a_81_8  & 1)*9+(#a_81_9  & 1)*10) >=55
 
}