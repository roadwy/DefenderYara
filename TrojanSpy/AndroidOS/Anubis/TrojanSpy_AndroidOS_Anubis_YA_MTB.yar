
rule TrojanSpy_AndroidOS_Anubis_YA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Anubis.YA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 33 4a 68 59 6d 4a 6c 63 69 42 6a 59 58 4a 6b 63 79 42 74 61 57 35 70 } //01 00 
		$a_00_1 = {61 48 52 74 62 47 78 76 59 32 74 6c 63 67 3d 3d } //01 00 
		$a_02_2 = {2f 6f 31 6f 2f 61 90 02 03 2e 70 68 70 90 00 } //01 00 
		$a_00_3 = {7c 53 74 61 72 74 20 69 6e 6a 65 63 74 69 6f 6e } //01 00 
		$a_00_4 = {50 47 46 74 62 33 56 75 64 44 34 3d } //01 00 
		$a_00_5 = {53 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}