
rule TrojanSpy_AndroidOS_Basbanke_C{
	meta:
		description = "TrojanSpy:AndroidOS/Basbanke.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 43 6c 69 63 61 58 65 59 } //01 00 
		$a_01_1 = {48 69 65 72 61 72 63 68 69 } //01 00 
		$a_01_2 = {50 75 78 61 72 4a 61 6e 65 6c 61 41 74 75 61 6c 4e 6f 64 65 } //01 00 
		$a_01_3 = {4f 75 45 73 63 72 65 76 65 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}