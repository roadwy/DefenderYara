
rule Trojan_Win64_Reflo_NR_MTB{
	meta:
		description = "Trojan:Win64/Reflo.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {74 0e 48 39 c3 74 0d b9 90 01 04 ff d6 eb e8 31 f6 eb 05 be 90 01 04 48 8b 1d 2e 3f 57 00 8b 03 ff c8 75 0c 90 00 } //01 00 
		$a_01_1 = {42 00 65 00 77 00 62 00 6f 00 64 00 66 00 65 00 21 00 4e 00 6a 00 64 00 73 00 70 00 21 00 45 00 66 00 77 00 6a 00 64 00 66 00 74 00 } //00 00  Bewbodfe!Njdsp!Efwjdft
	condition:
		any of ($a_*)
 
}