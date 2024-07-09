
rule Trojan_Win32_Fragtor_HBAI_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.HBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b c3 33 d4 0f b6 15 ?? ?? ?? ?? f5 3b e5 33 c2 81 e6 ff } //10
		$a_02_1 = {b2 08 66 d3 f2 13 d7 a1 ?? ?? ?? ?? 80 d6 ?? 0f ac ea ?? 83 c4 f8 0f b7 d4 } //10
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}