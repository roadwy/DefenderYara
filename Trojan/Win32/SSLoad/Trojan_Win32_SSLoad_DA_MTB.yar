
rule Trojan_Win32_SSLoad_DA_MTB{
	meta:
		description = "Trojan:Win32/SSLoad.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 f7 75 ?? 8a 44 15 ?? 30 81 ?? ?? ?? ?? 41 81 f9 d0 07 00 00 72 90 09 07 00 c7 45 } //1
		$a_03_1 = {33 d2 c7 45 [0-05] 8b c6 8d 0c 3e f7 75 ?? 03 d3 8a 44 15 ?? 8b 55 ?? 32 04 11 46 88 01 81 fe ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}