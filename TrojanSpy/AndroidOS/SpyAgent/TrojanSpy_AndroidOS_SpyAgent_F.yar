
rule TrojanSpy_AndroidOS_SpyAgent_F{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.F,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 73 44 65 6d 6f 33 2e 64 6c 6c } //01 00 
		$a_00_1 = {4b 55 52 42 41 4e 49 53 4d 49 } //01 00 
		$a_00_2 = {2e 50 68 6f 6e 65 63 61 6c 6c 52 65 63 65 69 76 65 72 2c 20 53 65 72 76 69 63 65 73 44 65 6d 6f 33 } //01 00 
		$a_00_3 = {54 61 73 6b 32 2e 4b 65 79 4c 69 73 74 65 6e 2c 20 53 65 72 76 69 63 65 73 44 65 6d 6f 33 } //00 00 
	condition:
		any of ($a_*)
 
}