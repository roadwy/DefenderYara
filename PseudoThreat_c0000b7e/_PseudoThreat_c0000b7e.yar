
rule _PseudoThreat_c0000b7e{
	meta:
		description = "!PseudoThreat_c0000b7e,SIGNATURE_TYPE_PEHSTR_EXT,ffffff92 01 ffffff92 01 06 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {6d 70 5f 66 69 6c 65 64 6f 77 6e 90 02 04 2e 70 68 70 3f 73 6e 3d 90 00 } //100
		$a_02_2 = {6d 70 5f 63 6e 74 73 90 02 04 2e 70 68 70 3f 73 6e 3d 90 00 } //100
		$a_02_3 = {63 3a 5c 6d 70 72 90 02 05 2e 69 6e 69 90 00 } //100
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {49 45 46 72 61 6d 65 } //1 IEFrame
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*100+(#a_02_2  & 1)*100+(#a_02_3  & 1)*100+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=402
 
}