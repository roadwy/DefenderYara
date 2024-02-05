
rule Trojan_Win32_Amadey_MZZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b c7 c1 e0 90 01 01 03 45 90 01 01 33 45 90 01 01 33 45 90 01 01 50 8d 45 90 01 01 50 e8 90 01 04 81 3d 90 01 08 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}