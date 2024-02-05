
rule Trojan_Win32_Cridex_OR_MTB{
	meta:
		description = "Trojan:Win32/Cridex.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 83 44 24 14 04 05 90 01 04 89 44 24 1c 89 02 ba 16 11 00 00 2b d6 a3 c8 c6 5e 00 8b 74 24 1c 03 d2 2b d1 8a c2 2a 44 24 0f 02 d8 83 6c 24 28 01 89 5c 24 10 0f 85 36 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}