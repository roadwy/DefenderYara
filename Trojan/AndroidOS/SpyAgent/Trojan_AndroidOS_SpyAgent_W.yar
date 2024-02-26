
rule Trojan_AndroidOS_SpyAgent_W{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.W,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 56 69 64 65 6f 20 5c 64 } //01 00  startVideo \d
		$a_01_1 = {2d 2d 20 20 46 72 6f 6e 74 20 43 61 6d 65 72 61 } //01 00  --  Front Camera
		$a_01_2 = {74 61 6b 65 70 69 63 20 5c 64 } //00 00  takepic \d
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SpyAgent_W_2{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.W,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 6e 75 73 63 72 65 61 74 65 73 } //02 00  onuscreates
		$a_01_1 = {70 68 69 73 64 61 74 61 73 65 74 75 70 } //02 00  phisdatasetup
		$a_01_2 = {2f 61 70 6b 66 72 6f 6d 68 65 6c 6c 74 6f 79 6f 75 66 6f 72 74 68 69 73 } //00 00  /apkfromhelltoyouforthis
	condition:
		any of ($a_*)
 
}