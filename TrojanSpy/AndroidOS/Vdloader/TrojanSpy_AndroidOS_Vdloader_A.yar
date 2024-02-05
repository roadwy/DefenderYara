
rule TrojanSpy_AndroidOS_Vdloader_A{
	meta:
		description = "TrojanSpy:AndroidOS/Vdloader.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 5f 50 48 4f 4e 45 5f 49 4e 46 4f } //01 00 
		$a_01_1 = {61 64 20 6d 75 73 74 20 62 65 20 67 6f 6e 65 2c } //01 00 
		$a_01_2 = {63 6e 2e 6e 65 6f 67 6f 75 } //01 00 
		$a_01_3 = {41 64 41 63 74 69 76 69 74 79 20 69 73 20 63 6c 6f 73 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}