
rule Trojan_Win32_SmokeLoader_RB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 a9 2a 6f db ad 44 ad 44 a8 68 ea 53 af af af af 44 a2 9c 90 5a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_RB_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2c 67 88 2a c7 84 24 90 01 04 60 c3 73 76 c7 84 24 90 01 04 41 59 8d 4d c7 84 24 90 01 04 9f f8 ff 08 c7 84 24 90 01 04 5f 05 09 1a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}