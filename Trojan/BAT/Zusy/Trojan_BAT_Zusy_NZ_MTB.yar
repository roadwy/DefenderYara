
rule Trojan_BAT_Zusy_NZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 68 00 00 0a 02 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 03 6f 90 01 01 00 00 0a 0a 73 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 23 00 00 06 90 00 } //01 00 
		$a_01_1 = {4d 65 6c 6f 6e 53 70 6f 6f 66 65 72 5f 62 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  MelonSpoofer_b2.Properties.Resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 28 06 00 00 06 75 90 01 03 1b 28 90 01 03 0a 13 04 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 3a 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff dd 90 01 03 ff 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 3a 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {4d 6b 77 69 6d 73 63 78 76 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Mkwimscxva.Properties.Resources
	condition:
		any of ($a_*)
 
}