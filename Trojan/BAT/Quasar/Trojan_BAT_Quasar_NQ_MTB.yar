
rule Trojan_BAT_Quasar_NQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 6f 65 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 06 28 90 01 01 00 00 06 0d 28 90 01 01 00 00 06 09 90 00 } //01 00 
		$a_01_1 = {62 72 61 76 65 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Quasar_NQ_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {17 8d 01 00 00 01 25 16 d0 90 01 01 00 00 01 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 75 90 01 01 00 00 01 14 6f 90 01 01 00 00 0a 75 90 01 01 00 00 1b 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 39 35 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Quasar_NQ_MTB_3{
	meta:
		description = "Trojan:BAT/Quasar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 2b 00 00 0a 72 90 01 03 70 6f 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 7e 90 01 03 04 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {50 6f 77 65 72 73 68 65 6c 6c 45 78 65 63 75 74 6f 72 58 6f 72 45 6e 63 6f 64 65 64 } //01 00 
		$a_01_2 = {43 6c 69 65 6e 74 5f 62 75 69 6c 74 5f 68 76 6e 63 } //00 00 
	condition:
		any of ($a_*)
 
}