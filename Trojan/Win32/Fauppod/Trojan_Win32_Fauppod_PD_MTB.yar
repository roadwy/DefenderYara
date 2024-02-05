
rule Trojan_Win32_Fauppod_PD_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 02 06 68 90 01 04 83 c4 04 8a 06 46 53 83 c4 04 32 02 88 07 47 89 c0 83 c2 01 90 90 83 ec 04 c7 04 24 90 01 04 83 c4 04 49 85 c9 75 90 01 01 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}