
rule Trojan_Win32_Remcos_PI_MTB{
	meta:
		description = "Trojan:Win32/Remcos.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 73 74 2e 74 68 67 } //01 00 
		$a_02_1 = {53 31 db 8b 04 8a 88 c7 88 e3 c1 e8 10 c1 e3 08 88 c3 89 1c 8a 49 79 90 01 01 5b 8b e5 5d c3 90 00 } //01 00 
		$a_02_2 = {8b c8 8b 44 24 90 01 01 8b 50 90 01 01 03 d6 8b 44 24 90 01 01 8b 40 90 01 01 03 44 24 90 01 01 e8 da d2 f8 ff 8b 44 24 90 01 01 8b 40 90 01 01 03 44 24 90 01 01 8b 54 24 90 01 01 89 42 90 01 01 8b 44 24 90 01 01 83 c0 90 01 01 89 44 24 90 01 01 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}