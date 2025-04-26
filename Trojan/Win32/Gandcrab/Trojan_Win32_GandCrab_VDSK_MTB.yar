
rule Trojan_Win32_GandCrab_VDSK_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 00 05 c3 9e 26 00 a3 90 09 0a 00 69 05 ?? ?? ?? ?? fd 43 03 00 } //1
		$a_00_1 = {8b 4d 08 30 04 0e 46 3b f7 7c } //1
		$a_00_2 = {8b 45 d4 c1 e0 04 03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 55 d4 c1 ea 05 03 55 e8 33 c2 8b 4d f4 } //2
		$a_02_3 = {33 c4 89 84 24 00 08 00 00 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 8d 0c 24 51 05 c3 9e 26 00 68 ?? ?? ?? ?? a3 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}