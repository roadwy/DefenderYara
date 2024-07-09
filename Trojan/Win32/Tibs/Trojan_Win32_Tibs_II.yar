
rule Trojan_Win32_Tibs_II{
	meta:
		description = "Trojan:Win32/Tibs.II,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 38 85 c0 75 90 14 c1 e8 ?? c1 e8 } //1
		$a_03_1 = {83 c8 ff 05 88 25 f4 0f e8 90 16 58 } //1
		$a_03_2 = {81 f2 54 a4 00 00 66 81 fa 19 fe 74 ?? 2d ?? ?? ?? ?? 2d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}