
rule Backdoor_Linux_Xnote_A{
	meta:
		description = "Backdoor:Linux/Xnote.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 2e 58 73 65 72 76 65 72 5f 6e 6f 74 65 00 } //1
		$a_00_1 = {61 6c 72 65 61 64 79 20 73 74 61 72 74 20 61 20 64 64 6f 73 20 73 79 6e 20 74 61 73 6b 20 00 } //1
		$a_00_2 = {2f 74 6d 70 2f 2e 77 71 34 73 4d 4c 41 72 58 77 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}