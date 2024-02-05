
rule Trojan_Win32_Raccoon_ET_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.ET!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 29 45 f4 8b 4d f4 c1 e1 04 89 4d e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 } //0a 00 
		$a_01_1 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0 c7 45 c4 00 00 00 00 8b 45 d8 01 45 c4 } //00 00 
	condition:
		any of ($a_*)
 
}