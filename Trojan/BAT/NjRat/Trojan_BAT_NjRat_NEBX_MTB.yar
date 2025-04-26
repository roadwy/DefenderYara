
rule Trojan_BAT_NjRat_NEBX_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 77 28 1a 00 00 06 28 31 00 00 0a 28 32 00 00 0a 13 71 11 71 6f 33 00 00 0a 0a 14 13 79 14 13 76 06 6f 34 00 00 0a 8e b7 16 fe 02 13 7e 11 7e 2c 25 } //10
		$a_01_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //2 DebuggerHiddenAttribute
		$a_01_2 = {57 69 6e 64 6f 77 73 2e 70 64 62 } //2 Windows.pdb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}