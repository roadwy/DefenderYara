
rule Trojan_BAT_RecordBreaker_RDE_MTB{
	meta:
		description = "Trojan:BAT/RecordBreaker.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {fe 0c 1f 00 fe 0c 17 00 46 fe 0c 03 00 61 52 fe 0c 17 00 20 01 00 00 00 58 fe 0e 17 00 fe 0c 1f 00 20 01 00 00 00 58 fe 0e 1f 00 } //01 00 
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 57 } //01 00 
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}