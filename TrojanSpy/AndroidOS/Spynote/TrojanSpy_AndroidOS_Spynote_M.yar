
rule TrojanSpy_AndroidOS_Spynote_M{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 72 72 61 79 44 6e 73 5f 4b 65 79 } //1 ArrayDns_Key
		$a_00_1 = {43 6f 6e 74 61 63 74 5f 73 65 72 76 65 72 30 30 30 } //1 Contact_server000
		$a_00_2 = {44 65 73 53 65 72 76 69 63 53 63 72 65 65 6e } //1 DesServicScreen
		$a_00_3 = {75 70 6c 6f 61 64 5f 66 69 6c 65 30 30 30 } //1 upload_file000
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}