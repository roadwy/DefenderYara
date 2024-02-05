
rule Ransom_MacOS_Filecoder_YC_MTB{
	meta:
		description = "Ransom:MacOS/Filecoder.YC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 6f 69 64 69 65 76 69 74 63 65 66 66 65 2f 6c 69 62 70 65 72 73 69 73 74 2f 72 65 6e 6e 75 72 2e 63 } //01 00 
		$a_00_1 = {2f 6c 69 62 74 70 79 72 63 2f 74 70 79 72 63 2e 63 } //01 00 
		$a_00_2 = {2f 74 6f 69 64 69 65 76 69 74 63 65 66 66 65 2f 6c 69 62 70 65 72 73 69 73 74 2f 70 65 72 73 69 73 74 2e 63 } //01 00 
		$a_00_3 = {49 4e 46 45 43 54 4f 52 20 4d 41 49 4e } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}