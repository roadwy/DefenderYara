
rule Trojan_Win32_FormBook_AA_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 68 00 6f 00 72 00 61 00 63 00 6f 00 63 00 65 00 6c 00 6f 00 73 00 63 00 68 00 69 00 73 00 69 00 73 00 } //01 00  thoracoceloschisis
		$a_01_1 = {73 00 79 00 6d 00 6f 00 6e 00 } //01 00  symon
		$a_01_2 = {73 00 75 00 73 00 70 00 65 00 63 00 74 00 65 00 64 00 } //01 00  suspected
		$a_01_3 = {66 00 69 00 6c 00 69 00 61 00 6c 00 69 00 74 00 79 00 } //01 00  filiality
		$a_01_4 = {44 00 6f 00 75 00 62 00 6c 00 } //01 00  Doubl
		$a_00_5 = {47 73 38 4c 48 73 7a 4a 48 73 } //01 00  Gs8LHszJHs
		$a_00_6 = {73 42 73 70 4b 42 73 } //01 00  sBspKBs
		$a_00_7 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}