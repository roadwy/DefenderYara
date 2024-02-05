
rule TrojanSpy_AndroidOS_Basbanke_A{
	meta:
		description = "TrojanSpy:AndroidOS/Basbanke.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 65 63 65 62 65 64 6f 72 44 61 64 6f 73 42 61 6e 6b 65 72 32 } //01 00 
		$a_00_1 = {69 64 73 65 63 75 72 69 74 79 2e 69 6e 69 } //01 00 
		$a_00_2 = {78 4d 65 6e 73 73 61 67 65 6d 5f 41 } //01 00 
		$a_00_3 = {64 61 74 61 3d 4c 45 52 50 49 53 7c 68 65 68 65 } //00 00 
	condition:
		any of ($a_*)
 
}