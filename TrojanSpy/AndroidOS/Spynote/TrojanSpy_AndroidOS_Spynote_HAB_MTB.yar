
rule TrojanSpy_AndroidOS_Spynote_HAB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.HAB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 62 6d 70 00 04 2e 67 69 66 00 05 2e 6a 70 65 67 00 04 2e 6a 70 67 00 04 2e 70 6e 67 00 05 2e 77 65 62 70 00 01 2f 00 1e 2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 65 2f 70 77 64 2e 74 65 78 74 00 0d 2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f 00 0d 2f 70 72 6f 63 2f 6d 65 6d 69 6e 66 6f 00 08 2f 73 64 63 61 72 64 2f 00 01 30 00 02 30 25 00 02 30 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}