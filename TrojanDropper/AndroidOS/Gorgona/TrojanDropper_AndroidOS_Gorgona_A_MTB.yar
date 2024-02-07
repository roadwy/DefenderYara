
rule TrojanDropper_AndroidOS_Gorgona_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Gorgona.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 65 72 52 65 73 74 61 72 74 65 72 53 65 72 76 69 63 65 } //01 00  WorkerRestarterService
		$a_00_1 = {49 6e 73 74 61 6c 6c 65 72 52 65 73 74 61 72 74 65 72 53 65 72 76 69 63 65 } //01 00  InstallerRestarterService
		$a_00_2 = {49 6e 6a 65 63 74 69 6f 6e 48 74 6d 6c 41 63 74 69 76 69 74 79 } //01 00  InjectionHtmlActivity
		$a_03_3 = {3a 00 1b 00 6e 20 90 01 02 04 00 0a 02 d8 03 00 ff df 02 02 7a 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 90 01 02 34 00 0a 02 df 02 02 62 8e 22 50 02 01 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}