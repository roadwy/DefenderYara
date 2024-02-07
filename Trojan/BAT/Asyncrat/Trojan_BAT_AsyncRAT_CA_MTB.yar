
rule Trojan_BAT_AsyncRAT_CA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {58 fe 0e 0a 00 91 fe 90 01 03 61 d2 9c fe 90 01 03 20 90 01 04 5f 20 90 01 04 40 90 01 04 fe 90 01 03 fe 90 01 03 58 fe 90 01 03 fe 90 01 03 20 90 01 04 64 fe 90 01 03 20 90 01 04 62 60 20 90 01 04 5a fe 90 01 03 fe 90 01 03 20 90 01 04 64 fe 90 01 03 20 90 01 04 62 60 fe 90 01 03 fe 90 01 03 20 90 01 04 58 fe 90 01 03 fe 90 01 03 6a 20 90 01 04 6a 3f 90 00 } //01 00 
		$a_81_1 = {63 75 63 6b 6f 6f 6d 6f 6e 2e 64 6c 6c } //01 00  cuckoomon.dll
		$a_81_2 = {53 78 49 6e 2e 64 6c 6c } //01 00  SxIn.dll
		$a_81_3 = {63 6d 64 76 72 74 33 32 2e 64 6c 6c } //01 00  cmdvrt32.dll
		$a_81_4 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //00 00  SbieDll.dll
	condition:
		any of ($a_*)
 
}