
rule Trojan_BAT_BlackGuard_ABG_MTB{
	meta:
		description = "Trojan:BAT/BlackGuard.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 40 1f 00 00 28 90 01 03 0a 20 f0 0f 00 00 28 90 01 03 0a 7e 01 00 00 04 7e 03 00 00 04 28 90 01 03 0a 0a 73 0e 00 00 0a 7e 02 00 00 04 06 6f 90 01 03 0a 20 77 32 00 00 28 90 01 03 0a 73 10 00 00 0a 25 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00 
		$a_01_2 = {65 6b 69 61 } //00 00 
	condition:
		any of ($a_*)
 
}