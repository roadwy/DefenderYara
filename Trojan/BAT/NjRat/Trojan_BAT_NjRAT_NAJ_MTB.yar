
rule Trojan_BAT_NjRAT_NAJ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {fe 0e 05 00 38 90 01 03 ff 07 14 72 90 01 03 70 18 8d 90 01 03 01 13 04 11 04 16 14 a2 00 11 04 17 14 a2 00 11 04 14 14 14 17 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Windows.g.resources
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}