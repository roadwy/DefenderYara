
rule TrojanSpy_AndroidOS_Spynote_O{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.O,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 65 73 75 6c 74 3d 6f 6b 26 61 63 74 69 6f 6e 3d 67 65 74 63 6f 6e 74 61 63 74 26 61 6e 64 72 6f 69 64 69 64 3d } //01 00  result=ok&action=getcontact&androidid=
		$a_00_1 = {26 69 73 62 61 6e 6b 3d } //01 00  &isbank=
		$a_00_2 = {6c 69 73 74 6e 75 6d 26 61 6e 64 72 6f 69 64 69 64 3d } //00 00  listnum&androidid=
	condition:
		any of ($a_*)
 
}