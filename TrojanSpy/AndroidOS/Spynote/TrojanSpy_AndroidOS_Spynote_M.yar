
rule TrojanSpy_AndroidOS_Spynote_M{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 72 72 61 79 44 6e 73 5f 4b 65 79 } //01 00  ArrayDns_Key
		$a_00_1 = {43 6f 6e 74 61 63 74 5f 73 65 72 76 65 72 30 30 30 } //01 00  Contact_server000
		$a_00_2 = {44 65 73 53 65 72 76 69 63 53 63 72 65 65 6e } //01 00  DesServicScreen
		$a_00_3 = {75 70 6c 6f 61 64 5f 66 69 6c 65 30 30 30 } //00 00  upload_file000
		$a_00_4 = {5d 04 00 } //00 82 
	condition:
		any of ($a_*)
 
}