
rule Trojan_AndroidOS_SpyAgent_M{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.M,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 65 61 64 53 4d 53 42 6f 78 } //02 00  readSMSBox
		$a_01_1 = {48 65 6c 6c 6f 20 74 68 65 72 65 2c 20 77 65 6c 63 6f 6d 65 20 74 6f 20 72 65 76 65 72 73 65 20 73 68 65 6c 6c 20 6f 66 } //02 00  Hello there, welcome to reverse shell of
		$a_01_2 = {74 61 6b 65 70 69 63 20 5c 64 } //02 00  takepic \d
		$a_01_3 = {73 74 6f 70 56 69 64 65 6f 31 32 33 } //00 00  stopVideo123
	condition:
		any of ($a_*)
 
}