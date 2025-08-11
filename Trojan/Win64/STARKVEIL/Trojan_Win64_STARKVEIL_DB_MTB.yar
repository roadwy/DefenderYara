
rule Trojan_Win64_STARKVEIL_DB_MTB{
	meta:
		description = "Trojan:Win64/STARKVEIL.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffcd 00 ffffffcd 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 3a 2f 77 69 6e 73 79 73 74 65 6d } //100 C:/winsystem
		$a_81_1 = {43 61 70 43 75 74 2e 70 64 62 } //100 CapCut.pdb
		$a_81_2 = {53 63 72 65 65 6e 54 6f 43 6c 69 65 6e 74 } //1 ScreenToClient
		$a_81_3 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_81_4 = {53 65 74 43 61 70 74 75 72 65 } //1 SetCapture
		$a_81_5 = {52 65 76 6f 6b 65 44 72 61 67 44 72 6f 70 } //1 RevokeDragDrop
		$a_81_6 = {72 75 73 74 5f 70 61 6e 69 63 } //1 rust_panic
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*100+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=205
 
}