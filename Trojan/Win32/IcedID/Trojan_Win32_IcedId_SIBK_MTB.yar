
rule Trojan_Win32_IcedId_SIBK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 77 75 6e 68 6b 71 6c 7a 6c 65 2e 64 6c 6c } //01 00 
		$a_03_1 = {c1 e5 07 8b 4c 24 90 01 01 c1 e9 90 01 01 89 f0 89 fe 89 cf ba 90 01 04 31 d7 89 eb 31 d3 41 b8 90 01 04 44 21 c7 83 e1 90 01 01 09 f9 89 f7 89 c6 44 21 c3 81 e5 90 01 04 09 dd 31 cd 45 0f be e9 89 e9 31 d1 b8 90 01 04 21 c1 bb 90 01 04 21 dd 09 cd 44 89 e9 31 d1 21 c1 41 21 dd 41 09 cd 8b 4c 24 90 01 01 ff c1 48 63 c1 48 03 44 24 90 01 01 41 31 ed 8b 54 24 90 01 01 ff c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_SIBK_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 31 48 c1 e2 90 01 01 48 0b c2 4c 8b c0 33 c9 b8 01 00 00 00 0f a2 89 44 24 90 01 01 89 5c 24 90 01 01 89 4c 24 90 01 01 89 54 24 90 01 01 0f 31 48 c1 e2 90 01 01 48 0b c2 49 2b c0 48 03 f8 ff 15 90 01 04 0f 31 48 c1 e2 90 01 01 90 90 48 0b c2 48 8b c8 0f 31 48 c1 e2 90 01 01 48 0b c2 48 2b c1 48 03 f0 48 83 ed 90 01 01 75 90 00 } //01 00 
		$a_03_1 = {45 33 c0 4c 8d 0d 90 01 04 49 2b c9 4b 8d 14 08 49 ff c0 8a 42 90 01 01 32 02 88 44 11 90 01 01 49 83 f8 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}