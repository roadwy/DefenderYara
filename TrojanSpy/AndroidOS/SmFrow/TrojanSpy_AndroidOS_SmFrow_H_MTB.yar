
rule TrojanSpy_AndroidOS_SmFrow_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmFrow.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 70 5f 73 74 61 74 65 2e 70 68 70 3f 74 65 6c 6e 75 6d 3d } //01 00  hp_state.php?telnum=
		$a_01_1 = {69 6e 64 65 78 2e 70 68 70 3f 74 79 70 65 3d 6a 6f 69 6e 26 74 65 6c 6e 75 6d 3d } //01 00  index.php?type=join&telnum=
		$a_01_2 = {43 6f 6e 6e 4d 61 63 68 69 6e 65 } //01 00  ConnMachine
		$a_01_3 = {67 65 74 4c 69 6e 65 31 4e 75 6d 62 65 72 } //01 00  getLine1Number
		$a_01_4 = {73 65 72 76 65 72 5f 75 72 6c } //00 00  server_url
	condition:
		any of ($a_*)
 
}