
rule TrojanDropper_AndroidOS_SAgnt_P_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6e 10 0d 00 ?? 00 0c 02 1a 03 ?? 00 71 10 ?? 00 03 00 0c 03 70 30 ?? 00 21 03 6e 10 ?? 00 01 00 1c 02 08 00 1a 03 ?? 00 71 10 ?? 00 03 00 0c 03 12 04 6e 30 } //1
		$a_03_1 = {4d 12 0f 04 4d 05 0f 02 13 11 03 00 4d 0d 0f 11 6e 20 ?? 00 f9 00 0c 0f 6e 10 ?? 00 07 00 0c 12 23 00 ?? 00 4d 12 00 03 62 12 ?? 00 4d 12 00 04 13 10 00 00 4d 10 00 02 13 10 03 00 4d 0b 00 10 6e 20 ?? 00 0f 00 0c 01 28 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}