
rule Trojan_AndroidOS_Spyagent_T{
	meta:
		description = "Trojan:AndroidOS/Spyagent.T,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 45 6e 61 62 6c 65 52 65 61 64 46 69 6c 65 73 } //01 00  getEnableReadFiles
		$a_01_1 = {67 65 74 4e 65 77 53 65 72 76 65 72 55 72 6c 33 } //01 00  getNewServerUrl3
		$a_01_2 = {69 73 43 4f 6e 69 6f 6e 45 6e 61 62 6c 65 64 } //00 00  isCOnionEnabled
	condition:
		any of ($a_*)
 
}