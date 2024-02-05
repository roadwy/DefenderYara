
rule Trojan_Win32_Raccoon_BA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ec 08 c6 05 90 01 04 88 c6 05 90 01 04 61 c6 05 90 01 04 60 c6 05 90 01 04 72 c6 05 90 01 04 6f c6 05 90 01 04 00 c6 05 90 01 04 74 90 02 20 7f c6 05 90 01 04 86 c6 05 90 01 04 88 c6 05 90 01 04 50 c6 05 90 01 04 76 c6 05 90 01 04 63 c6 05 90 01 04 65 90 00 } //01 00 
		$a_00_1 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0 } //00 00 
	condition:
		any of ($a_*)
 
}