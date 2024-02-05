
rule Trojan_BAT_AsyncRAT_NAR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f f8 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 08 90 00 } //01 00 
		$a_01_1 = {41 73 79 6e 63 52 41 54 2d 43 6c 69 65 6e 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AsyncRAT_NAR_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {38 9d 00 00 00 26 20 90 01 03 00 38 90 01 03 00 20 90 01 03 b0 17 63 20 90 01 03 02 61 1a 63 20 90 01 03 02 58 07 5b 0b 20 90 01 03 00 fe 90 01 02 00 28 90 01 03 06 39 90 01 03 00 38 90 01 03 00 38 90 01 03 00 12 00 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}