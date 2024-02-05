
rule TrojanSpy_AndroidOS_Banker_AL_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AL!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {64 65 76 69 6c 2f 73 6b 2f 53 6d 73 52 65 63 65 69 76 65 72 } //05 00 
		$a_01_1 = {67 65 74 42 42 56 41 50 61 73 73 77 6f 72 64 } //01 00 
		$a_01_2 = {63 68 65 63 6b 43 61 6c 6c 69 6e 67 4f 72 53 65 6c 66 50 65 72 6d 69 73 73 69 6f 6e } //01 00 
		$a_01_3 = {63 68 65 63 6b 52 65 61 64 41 6e 64 52 65 63 65 69 76 65 41 6e 64 53 65 6e 64 53 6d 73 } //00 00 
	condition:
		any of ($a_*)
 
}