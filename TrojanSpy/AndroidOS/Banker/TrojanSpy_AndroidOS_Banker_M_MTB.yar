
rule TrojanSpy_AndroidOS_Banker_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 03 71 10 ?? ?? 04 00 0a 05 35 53 ?? ?? 71 20 ?? ?? 34 00 0c 05 1f 05 28 00 12 06 13 07 64 00 35 76 0f 00 21 57 35 76 0c 00 48 07 05 06 d7 77 88 00 8d 77 4f 07 05 06 d8 06 06 01 28 f0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}