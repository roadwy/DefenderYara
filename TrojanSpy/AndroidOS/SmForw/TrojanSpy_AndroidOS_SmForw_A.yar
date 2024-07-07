
rule TrojanSpy_AndroidOS_SmForw_A{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 65 67 44 50 4d 41 63 74 69 76 69 74 79 } //1 RegDPMActivity
		$a_00_1 = {43 61 6c 6c 53 74 61 74 65 4c 69 73 74 6e 65 72 } //1 CallStateListner
		$a_00_2 = {65 6e 64 20 63 61 6c 6c 21 21 } //1 end call!!
		$a_00_3 = {67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 3f 74 65 6c 6e 75 6d 3d } //1 getsmsblockstate.php?telnum=
		$a_00_4 = {2f 50 72 65 6f 64 69 63 53 65 72 76 69 63 65 3b } //1 /PreodicService;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}