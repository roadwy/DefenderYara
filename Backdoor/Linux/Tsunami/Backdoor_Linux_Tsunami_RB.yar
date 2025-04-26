
rule Backdoor_Linux_Tsunami_RB{
	meta:
		description = "Backdoor:Linux/Tsunami.RB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 75 73 79 62 6f 74 6e 65 74 } //1 busybotnet
		$a_01_1 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } //1 7ujMko0admin
		$a_01_2 = {66 75 63 6b 65 72 } //1 fucker
		$a_01_3 = {6d 61 78 69 64 65 64 } //1 maxided
		$a_01_4 = {67 61 79 62 6f 74 } //1 gaybot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}