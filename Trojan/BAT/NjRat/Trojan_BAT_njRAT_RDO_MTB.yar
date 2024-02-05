
rule Trojan_BAT_njRAT_RDO_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 36 31 66 64 36 39 33 2d 64 35 65 64 2d 34 66 32 32 2d 61 34 34 31 2d 35 33 61 30 65 30 64 35 32 36 32 62 } //01 00 
		$a_01_1 = {56 00 6f 00 6f 00 6c 00 79 00 20 00 4e 00 62 00 61 00 } //02 00 
		$a_01_2 = {fe 0c 05 00 fe 0c 06 00 8f 16 00 00 01 25 71 16 00 00 01 fe 0c 06 00 fe 09 04 00 58 20 ff 00 00 00 5f d2 61 d2 81 16 00 00 01 20 14 00 00 00 fe 0e 12 00 } //00 00 
	condition:
		any of ($a_*)
 
}