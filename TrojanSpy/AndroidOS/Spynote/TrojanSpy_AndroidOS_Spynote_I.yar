
rule TrojanSpy_AndroidOS_Spynote_I{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.I,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {44 65 76 69 63 65 69 6e 66 6f 20 69 73 20 4f 4b } //1 Deviceinfo is OK
		$a_00_1 = {75 70 6c 6f 61 64 26 61 6e 64 72 6f 69 64 69 64 3d } //1 upload&androidid=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}