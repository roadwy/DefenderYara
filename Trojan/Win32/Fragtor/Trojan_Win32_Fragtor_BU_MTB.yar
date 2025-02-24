
rule Trojan_Win32_Fragtor_BU_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 08 89 45 c4 8b d8 0f b6 04 37 6a 04 8a 84 18 ?? ?? ?? ?? 30 04 32 46 58 3b f0 72 } //2
		$a_01_1 = {2b c1 8a 4d f3 8a 44 30 03 32 c1 88 44 37 03 83 c6 04 8b 43 04 40 c1 e0 04 3b f0 0f 82 } //2
		$a_01_2 = {52 65 71 75 65 73 74 2e 64 6c 6c 00 63 31 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}