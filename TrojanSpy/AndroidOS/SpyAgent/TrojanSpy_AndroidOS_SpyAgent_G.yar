
rule TrojanSpy_AndroidOS_SpyAgent_G{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.G,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 64 65 76 69 63 65 65 2e 61 70 6b } //01 00  /devicee.apk
		$a_00_1 = {72 65 6c 61 78 5f 63 75 64 64 6c 65 2e 70 68 70 } //01 00  relax_cuddle.php
		$a_00_2 = {6f 74 68 65 72 61 70 6b 69 6e 73 74 } //00 00  otherapkinst
	condition:
		any of ($a_*)
 
}