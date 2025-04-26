
rule TrojanSpy_AndroidOS_SAgnt_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {46 06 03 01 6e 10 21 00 06 00 0c 00 1a 07 03 00 6e 20 38 00 70 00 0a 00 38 00 30 00 } //1
		$a_00_1 = {6e 10 05 00 06 00 0c 01 54 60 03 00 71 10 2e 00 00 00 0c 00 6e 10 33 00 00 00 0c 00 1f 00 03 00 5b 60 04 00 1c 00 03 00 1a 02 4d 00 12 13 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}