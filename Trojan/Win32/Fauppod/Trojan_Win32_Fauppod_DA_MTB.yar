
rule Trojan_Win32_Fauppod_DA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 06 46 83 ec 04 c7 04 24 90 01 04 83 c4 04 51 83 c4 04 32 02 90 01 01 88 07 47 90 01 01 68 90 01 04 83 c4 04 83 c2 01 49 90 01 01 85 c9 75 90 00 } //0a 00 
		$a_03_1 = {8a 06 46 32 02 68 90 01 04 83 c4 04 88 07 83 c7 01 89 c0 83 ec 04 c7 04 24 90 01 04 83 c4 04 42 90 01 01 50 83 c4 04 49 90 02 02 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}