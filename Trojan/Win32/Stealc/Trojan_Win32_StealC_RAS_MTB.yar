
rule Trojan_Win32_StealC_RAS_MTB{
	meta:
		description = "Trojan:Win32/StealC.RAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 8b cb c1 e1 04 03 4c 24 3c 8b c3 c1 e8 05 03 44 24 38 8d 14 2b 33 ca 89 44 24 18 89 4c 24 14 89 35 90 01 04 8b 44 24 18 01 05 84 40 7b 00 a1 90 01 04 89 44 24 28 89 74 24 18 90 00 } //01 00 
		$a_03_1 = {8d 04 2f 33 f0 8b 44 24 90 01 01 33 c6 2b d8 81 c5 47 86 c8 61 ff 4c 24 20 89 44 24 14 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}