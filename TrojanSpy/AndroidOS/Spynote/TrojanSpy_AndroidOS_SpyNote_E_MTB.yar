
rule TrojanSpy_AndroidOS_SpyNote_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyNote.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 02 12 13 33 31 12 00 62 01 ?? ?? 38 01 0b 00 13 01 f4 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 28 28 60 01 ?? ?? 33 31 12 00 62 01 ?? ?? 38 01 0b 00 13 01 f5 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 28 14 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}