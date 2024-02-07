
rule TrojanProxy_Win32_Cimuz_G{
	meta:
		description = "TrojanProxy:Win32/Cimuz.G,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 35 38 2e 36 35 2e 32 33 39 2e 38 32 } //01 00  http://58.65.239.82
		$a_01_1 = {6d 63 61 66 65 65 } //01 00  mcafee
		$a_01_2 = {4b 61 73 70 65 72 73 6b 79 } //01 00  Kaspersky
		$a_01_3 = {73 79 6d 61 6e 74 65 63 } //00 00  symantec
	condition:
		any of ($a_*)
 
}