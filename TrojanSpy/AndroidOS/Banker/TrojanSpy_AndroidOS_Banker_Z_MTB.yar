
rule TrojanSpy_AndroidOS_Banker_Z_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 12 21 b3 10 23 02 62 01 12 03 35 03 19 00 92 04 01 03 d8 05 04 02 6e 30 ?? ?? 46 05 0c 04 13 05 10 00 71 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0a 04 4f 04 02 03 d8 03 03 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}