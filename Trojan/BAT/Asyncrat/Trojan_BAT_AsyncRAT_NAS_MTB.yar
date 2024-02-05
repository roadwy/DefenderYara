
rule Trojan_BAT_AsyncRAT_NAS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {64 60 fe 0c 14 00 61 fe 90 01 02 00 fe 90 01 02 00 20 90 01 03 55 5f fe 90 01 02 00 fe 90 01 02 00 20 90 01 03 aa 5f fe 90 01 02 00 fe 90 01 02 00 20 90 01 03 00 64 fe 90 01 02 00 20 90 01 03 00 62 60 90 00 } //01 00 
		$a_01_1 = {50 79 4c 69 62 48 6f 73 74 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AsyncRAT_NAS_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.NAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {94 5b fe 0e 02 00 fe 90 01 02 00 20 90 01 03 1d 5a 20 90 01 03 79 61 38 90 01 03 ff 38 90 01 03 00 fe 90 01 02 00 20 90 01 03 7d 5a 20 90 01 03 ae 61 38 90 01 03 ff fe 90 01 02 00 20 90 01 03 00 91 fe 90 01 02 00 20 90 01 03 00 91 20 90 01 03 00 62 60 90 00 } //01 00 
		$a_01_1 = {64 75 75 6b 75 6b 66 64 63 79 65 66 66 64 74 6d 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}