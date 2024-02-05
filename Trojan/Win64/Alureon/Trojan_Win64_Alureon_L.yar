
rule Trojan_Win64_Alureon_L{
	meta:
		description = "Trojan:Win64/Alureon.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 49 6e 6a 65 63 74 36 34 53 74 61 72 74 00 90 02 10 49 6e 6a 65 63 74 36 34 45 6e 64 00 90 00 } //01 00 
		$a_03_1 = {0f b7 40 04 3d 64 86 00 00 75 0e 48 8b 44 24 90 01 01 48 8b 40 30 48 89 44 24 90 01 01 48 8b 44 24 90 01 01 0f b7 40 04 3d 4c 01 00 00 75 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}