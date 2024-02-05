
rule Adware_AndroidOS_Ashas_A{
	meta:
		description = "Adware:AndroidOS/Ashas.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 53 48 41 53 } //02 00 
		$a_00_1 = {43 4f 44 45 5f 43 4c 49 45 4e 54 5f 43 4f 4e 46 49 47 } //02 00 
		$a_00_2 = {41 4c 41 52 4d 5f 53 43 48 45 44 55 4c 45 5f 4d 49 4e 55 54 45 53 } //01 00 
		$a_01_3 = {41 53 61 64 73 64 6b } //01 00 
		$a_00_4 = {46 69 72 73 74 52 75 6e 53 65 72 76 69 63 65 20 6f 6e 43 72 65 61 74 65 } //00 00 
		$a_00_5 = {5d 04 00 00 94 90 } //04 00 
	condition:
		any of ($a_*)
 
}