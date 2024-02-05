
rule TrojanSpy_Win32_VB_ED{
	meta:
		description = "TrojanSpy:Win32/VB.ED,SIGNATURE_TYPE_PEHSTR,07 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 00 4e 00 6f 00 74 00 50 00 48 00 50 00 20 00 2b 00 52 00 53 00 52 00 43 00 20 00 53 00 51 00 6c 00 69 00 74 00 65 00 5c 00 73 00 6d 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_01_1 = {69 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 } //01 00 
		$a_01_2 = {2d 00 44 00 65 00 76 00 2d 00 50 00 6f 00 69 00 6e 00 74 00 2e 00 43 00 6f 00 4d 00 } //01 00 
		$a_01_3 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 } //01 00 
		$a_01_4 = {4e 00 6f 00 2d 00 49 00 50 00 20 00 6e 00 6f 00 74 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 2e 00 } //01 00 
		$a_01_5 = {59 00 61 00 68 00 6f 00 6f 00 21 00 20 00 45 00 54 00 43 00 } //01 00 
		$a_01_6 = {46 00 69 00 72 00 65 00 66 00 6f 00 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}