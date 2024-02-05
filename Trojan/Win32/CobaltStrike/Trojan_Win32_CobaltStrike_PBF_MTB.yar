
rule Trojan_Win32_CobaltStrike_PBF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {da 8b db c1 ee 1d 89 1d 90 01 04 42 81 2d 90 01 04 28 e7 af 8d c1 c2 0e 0b c3 81 eb 81 09 dd 44 bb a2 d4 a3 32 4b f7 c1 90 01 04 72 90 01 01 bb 90 01 04 03 f8 2b d1 ff c9 75 b7 90 00 } //01 00 
		$a_03_1 = {c1 c6 05 4b 0b c5 47 81 f0 90 01 04 f7 da 81 f7 90 01 04 21 15 90 01 04 c1 ea 1f c1 e6 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}