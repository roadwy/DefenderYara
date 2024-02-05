
rule TrojanSpy_AndroidOS_Origami_z{
	meta:
		description = "TrojanSpy:AndroidOS/Origami.z,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 61 6d 72 3a 3a 41 64 64 65 64 } //01 00 
		$a_01_1 = {43 68 65 63 6b 69 6e 67 20 46 6f 72 20 55 70 64 61 74 65 } //01 00 
		$a_00_2 = {31 32 33 34 35 36 37 38 39 30 33 32 31 34 35 } //01 00 
		$a_01_3 = {4c 30 46 75 5a 48 4a 76 61 57 51 76 4c 6e 4e 35 63 33 52 6c 62 53 38 3d } //00 00 
	condition:
		any of ($a_*)
 
}