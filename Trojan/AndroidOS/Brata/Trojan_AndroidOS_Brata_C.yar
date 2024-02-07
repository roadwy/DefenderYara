
rule Trojan_AndroidOS_Brata_C{
	meta:
		description = "Trojan:AndroidOS/Brata.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 70 6d 73 65 74 63 6f 6d 70 6f 6e 65 6e 74 65 6e 61 62 6c 65 64 73 65 74 74 69 6e 67 } //01 00  _pmsetcomponentenabledsetting
		$a_00_1 = {5f 63 61 6e 64 72 61 77 6f 76 65 72 6c 61 79 73 } //01 00  _candrawoverlays
		$a_00_2 = {5f 63 61 6e 77 72 69 74 65 74 6f 73 79 73 74 65 6d 73 65 74 74 69 6e 67 73 } //01 00  _canwritetosystemsettings
		$a_00_3 = {5f 61 63 74 69 76 61 74 65 61 6c 6c 70 65 72 6d 73 } //00 00  _activateallperms
	condition:
		any of ($a_*)
 
}