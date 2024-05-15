
rule Trojan_BAT_DarkTortilla_ND_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 74 0b 00 00 1b 28 90 01 03 06 14 14 14 1a 20 90 01 03 64 28 54 02 00 06 16 8d 90 01 03 01 14 14 14 28 90 01 03 0a 74 0b 00 00 1b 90 00 } //01 00 
		$a_01_1 = {45 64 33 77 31 2e 48 4b 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Ed3w1.HKs.resources
	condition:
		any of ($a_*)
 
}