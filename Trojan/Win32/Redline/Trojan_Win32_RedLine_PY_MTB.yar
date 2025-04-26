
rule Trojan_Win32_RedLine_PY_MTB{
	meta:
		description = "Trojan:Win32/RedLine.PY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 84 24 a8 01 00 00 ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 a4 24 b4 00 00 00 8b 84 24 b4 00 00 00 81 84 24 a4 01 00 00 ?? ?? ?? ?? ff d7 6a 00 ff d3 81 fe 56 53 1c 00 7f ?? 46 81 fe 44 ad cd 13 0f 8c } //1
		$a_01_1 = {73 00 65 00 79 00 6f 00 78 00 65 00 64 00 65 00 64 00 75 00 64 00 69 00 62 00 61 00 72 00 75 00 78 00 75 00 66 00 61 00 79 00 75 00 76 00 69 00 } //1 seyoxededudibaruxufayuvi
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}