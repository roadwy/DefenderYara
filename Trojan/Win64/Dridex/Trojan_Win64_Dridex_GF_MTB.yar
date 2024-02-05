
rule Trojan_Win64_Dridex_GF_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {4c 89 d9 44 89 44 24 90 01 01 41 89 c0 44 89 54 24 90 01 01 e8 90 01 04 48 8b 8c 24 90 01 04 48 8b 54 24 90 01 01 48 81 ca 90 01 04 48 89 94 24 90 01 04 e8 90 00 } //0a 00 
		$a_80_1 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  0a 00 
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  00 00 
	condition:
		any of ($a_*)
 
}