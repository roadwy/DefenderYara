
rule Trojan_Win32_Fauppod_PA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8a 06 83 c6 01 83 ec 04 c7 04 24 90 02 04 83 c4 04 83 ec 04 c7 04 24 90 02 04 83 c4 04 32 02 88 07 47 51 83 c4 04 42 83 ec 04 c7 04 24 90 02 04 83 c4 04 53 83 c4 04 49 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}