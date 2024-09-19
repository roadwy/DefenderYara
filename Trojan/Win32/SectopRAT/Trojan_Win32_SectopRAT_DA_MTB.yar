
rule Trojan_Win32_SectopRAT_DA_MTB{
	meta:
		description = "Trojan:Win32/SectopRAT.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 f9 d9 32 00 00 74 ?? 31 d2 89 c8 bb 17 00 00 00 f7 f3 0f b6 81 ?? ?? ?? ?? 0f b6 9a ?? ?? ?? ?? 31 d8 88 81 ?? ?? ?? ?? 41 eb } //1
		$a_03_1 = {33 d2 c7 44 24 ?? ?? ?? ?? ?? 8b c6 8d 0c 1e f7 74 24 ?? 03 d7 8a 44 14 ?? 32 04 29 46 88 01 81 fe 00 36 0d 00 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}