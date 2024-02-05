
rule Trojan_Win32_Fauppod_PF_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 02 06 83 c6 01 8a 46 90 01 01 89 c0 32 02 88 07 47 56 83 c4 04 83 c2 01 49 51 83 c4 04 90 90 85 c9 75 90 01 01 61 c9 c2 10 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}