
rule Trojan_Win32_Slepak_DED_MTB{
	meta:
		description = "Trojan:Win32/Slepak.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 54 24 2c 0f b6 c0 66 2b c2 8b 54 24 28 66 2b c7 0f b7 c8 a1 90 01 04 89 02 83 c2 04 8a 44 24 32 2a c1 89 54 24 28 8b 54 24 2c 04 5e ff 4c 24 24 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}