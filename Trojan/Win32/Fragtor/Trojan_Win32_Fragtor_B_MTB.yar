
rule Trojan_Win32_Fragtor_B_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 29 44 24 60 0f 29 44 24 70 8b 91 ?? ?? ?? ?? 33 54 08 04 89 54 0c 64 83 c1 04 83 f9 20 72 ea } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fragtor_B_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b c7 33 c9 ba 10 00 00 00 e8 ?? ?? ?? ?? 89 5f 0c 33 c0 89 47 04 c6 47 08 7f c6 47 09 01 33 c0 89 07 bb 30 00 00 00 8d ?? ?? 50 57 6a 00 e8 ?? ?? ?? ?? 8b f0 81 07 40 77 1b 00 4b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}