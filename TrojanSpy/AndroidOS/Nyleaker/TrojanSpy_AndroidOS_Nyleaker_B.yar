
rule TrojanSpy_AndroidOS_Nyleaker_B{
	meta:
		description = "TrojanSpy:AndroidOS/Nyleaker.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 65 74 44 65 6c 69 76 65 72 79 52 65 63 65 69 76 65 72 50 68 6f 6e 65 } //01 00 
		$a_00_1 = {53 65 74 49 63 6f 6e 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_2 = {46 69 6e 67 65 72 53 65 63 75 72 69 74 79 53 63 61 6e 6e 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}