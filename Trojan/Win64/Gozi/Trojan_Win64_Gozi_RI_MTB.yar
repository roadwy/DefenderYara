
rule Trojan_Win64_Gozi_RI_MTB{
	meta:
		description = "Trojan:Win64/Gozi.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 02 41 b9 5f f3 6e 3c 69 c0 0d 66 19 00 05 5f f3 6e 3c 89 01 69 c0 0d 66 19 00 44 8d 80 5f f3 6e 3c 66 44 89 41 04 45 69 c0 0d 66 19 00 45 03 c1 48 83 c1 08 66 44 89 41 fe 44 89 02 41 b8 08 00 00 00 8b 02 69 c0 0d 66 19 00 41 03 c1 88 01 48 83 c1 01 49 83 e8 01 89 02 } //00 00 
	condition:
		any of ($a_*)
 
}