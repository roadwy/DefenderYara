
rule Trojan_Win32_Amadey_TRE_MTB{
	meta:
		description = "Trojan:Win32/Amadey.TRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8d 0c 37 31 4c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}