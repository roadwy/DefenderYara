
rule Trojan_BAT_Fauppod_CB_MTB{
	meta:
		description = "Trojan:BAT/Fauppod.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 70 6b 51 6c 73 36 77 48 4b 70 6c 6e 67 37 6c 39 66 58 } //1 jpkQls6wHKplng7l9fX
		$a_01_1 = {53 79 73 74 65 6d 4d 61 6e 61 67 65 72 2e 66 72 6d 42 6f 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //1 SystemManager.frmBoard.resources
		$a_01_2 = {53 79 73 74 65 6d 4d 61 6e 61 67 65 72 2e 49 4a 53 46 49 48 42 2e 72 65 73 6f 75 72 63 65 73 } //1 SystemManager.IJSFIHB.resources
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}