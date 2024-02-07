
rule Trojan_Win64_IcedID_BL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {42 31 04 01 49 83 c0 04 8b 83 a0 00 00 00 33 43 0c 83 f0 0e 89 43 0c 8b 83 a0 00 00 00 83 e8 0e 31 43 10 b8 14 00 00 00 2b 83 38 01 00 00 01 43 48 8b 4b 10 44 89 8b b8 00 00 00 8d 81 90 02 04 8b 8b a0 00 00 00 31 43 40 2b 4b 40 8b 43 10 90 00 } //01 00 
		$a_01_1 = {48 63 72 7a 61 34 68 32 } //00 00  Hcrza4h2
	condition:
		any of ($a_*)
 
}