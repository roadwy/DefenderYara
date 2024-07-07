
rule TrojanSpy_AndroidOS_Banker_J_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {12 00 21 81 23 11 c7 00 01 02 01 23 21 84 35 40 35 00 d8 02 02 01 d5 22 ff 00 54 74 12 00 48 04 04 02 b0 43 d5 33 ff 00 54 74 12 00 48 04 04 03 54 75 12 00 54 76 12 00 48 06 06 02 4f 06 05 03 54 75 12 00 4f 04 05 02 54 74 12 00 48 04 04 02 54 75 12 00 48 05 05 03 b0 54 d5 44 ff 00 54 75 12 00 48 04 05 04 48 05 08 00 b7 54 8d 44 4f 04 01 00 d8 00 00 01 28 cb 11 01 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}