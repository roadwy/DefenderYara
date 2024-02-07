
rule Trojan_BAT_DarkTortilla_MBW_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 03 8c 90 01 01 00 00 01 a2 25 0b 14 14 17 8d 90 01 01 00 00 01 25 16 17 9c 25 0c 28 90 01 01 00 00 0a 0d 19 13 05 2b 8a 90 00 } //01 00 
		$a_01_1 = {43 6e 34 64 30 4e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  Cn4d0N.Resources.resource
		$a_01_2 = {34 34 65 36 61 62 32 39 37 39 62 66 } //00 00  44e6ab2979bf
	condition:
		any of ($a_*)
 
}