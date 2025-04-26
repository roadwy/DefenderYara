
rule Trojan_Win32_StealC_HOK_MTB{
	meta:
		description = "Trojan:Win32/StealC.HOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 03 44 24 28 8b cf c1 e1 04 03 4c 24 34 8d 14 2f 33 c1 33 c2 2b d8 8b c3 c1 e0 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 44 24 14 8b 44 24 24 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 75 } //1
		$a_03_1 = {8d 04 2b 33 f0 8b 44 24 ?? 33 c6 2b f8 81 c5 47 86 c8 61 ff 4c 24 1c 89 44 24 14 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}