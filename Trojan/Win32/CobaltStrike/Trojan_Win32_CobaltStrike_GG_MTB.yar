
rule Trojan_Win32_CobaltStrike_GG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 b8 00 30 00 00 41 b9 40 00 00 00 ff 15 } //01 00 
		$a_01_1 = {74 65 6d 70 5c 70 61 63 6b 65 64 36 34 2d 74 65 6d 70 2e 70 64 62 } //01 00  temp\packed64-temp.pdb
		$a_03_2 = {09 fb 31 d3 f7 d6 09 de 89 f2 f7 d2 21 ea f7 d5 21 f5 09 d5 89 ca 81 e2 90 01 04 41 81 e3 90 01 04 41 09 d3 44 09 c9 41 81 e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}