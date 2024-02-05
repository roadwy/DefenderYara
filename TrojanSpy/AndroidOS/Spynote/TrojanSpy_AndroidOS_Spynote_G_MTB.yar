
rule TrojanSpy_AndroidOS_Spynote_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 67 65 74 73 63 72 65 61 6d 53 7a } //01 00 
		$a_01_1 = {52 6e 67 52 6f 76 65 72 } //01 00 
		$a_01_2 = {73 6e 64 64 61 74 61 53 53 4d 53 } //01 00 
		$a_01_3 = {46 6c 61 66 68 53 74 6f 70 } //01 00 
		$a_01_4 = {70 72 6f 63 65 6b 69 6c 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}