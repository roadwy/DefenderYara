
rule Trojan_Win32_GandCrab_VDSK_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 05 c3 9e 26 00 a3 90 09 0a 00 69 05 90 01 04 fd 43 03 00 90 00 } //01 00 
		$a_00_1 = {8b 4d 08 30 04 0e 46 3b f7 7c } //02 00 
		$a_00_2 = {8b 45 d4 c1 e0 04 03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 55 d4 c1 ea 05 03 55 e8 33 c2 8b 4d f4 } //02 00 
		$a_02_3 = {33 c4 89 84 24 00 08 00 00 a1 90 01 04 69 c0 fd 43 03 00 8d 0c 24 51 05 c3 9e 26 00 68 90 01 04 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}