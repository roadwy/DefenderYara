
rule Trojan_AndroidOS_Fobus_A{
	meta:
		description = "Trojan:AndroidOS/Fobus.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6c 65 62 31 32 38 54 6f 49 6e 74 } //01 00  Uleb128ToInt
		$a_01_1 = {61 64 64 5a 69 70 54 6f 44 65 78 } //00 00  addZipToDex
	condition:
		any of ($a_*)
 
}