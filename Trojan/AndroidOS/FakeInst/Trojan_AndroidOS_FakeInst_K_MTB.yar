
rule Trojan_AndroidOS_FakeInst_K_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //02 00  killProcess
		$a_03_1 = {12 04 23 71 90 01 01 02 28 02 b0 26 8d 62 4f 02 01 04 d8 05 05 01 d8 04 04 01 33 74 90 02 05 12 02 70 30 90 02 05 10 02 6e 10 90 02 05 00 00 0c 00 11 00 48 02 03 05 90 00 } //02 00 
		$a_03_2 = {12 f4 da 08 08 04 d8 08 08 01 62 05 c0 05 22 00 01 02 23 81 5d 02 d8 08 08 ff 90 02 05 91 02 06 02 d8 06 02 fe d8 04 04 01 8d 62 4f 02 01 04 33 84 90 02 05 12 02 70 30 90 02 05 10 02 11 00 d8 07 07 01 48 02 05 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}