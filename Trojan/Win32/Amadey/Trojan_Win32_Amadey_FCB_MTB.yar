
rule Trojan_Win32_Amadey_FCB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.FCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 20 03 c3 33 ca 33 c8 2b f9 8b cf c1 e1 04 c7 05 90 01 04 00 00 00 00 89 4c 24 14 8b 44 24 28 01 44 24 14 81 3d 90 01 04 be 01 00 00 8d 2c 3b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}