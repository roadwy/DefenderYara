
rule Trojan_Win32_Fauppod_PL_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 01 01 90 90 90 90 8a 06 46 68 90 01 04 83 c4 04 68 90 01 04 83 c4 04 32 02 89 c0 83 c7 01 88 47 90 01 01 68 90 01 04 83 c4 04 42 68 90 01 04 83 c4 04 90 90 49 68 90 01 04 83 c4 04 89 c0 85 c9 75 90 01 01 61 c9 c2 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}