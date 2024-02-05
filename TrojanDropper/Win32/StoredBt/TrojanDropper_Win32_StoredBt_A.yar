
rule TrojanDropper_Win32_StoredBt_A{
	meta:
		description = "TrojanDropper:Win32/StoredBt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00 
		$a_01_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 3a 72 65 70 65 61 74 5f 64 65 6c } //01 00 
		$a_01_2 = {72 75 6e 33 32 77 2e 62 61 74 } //01 00 
		$a_01_3 = {6e 74 25 64 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}