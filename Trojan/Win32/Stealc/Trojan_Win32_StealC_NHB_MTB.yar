
rule Trojan_Win32_StealC_NHB_MTB{
	meta:
		description = "Trojan:Win32/StealC.NHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 74 24 48 31 7c 24 14 89 74 24 24 89 2d ?? ?? ?? ?? 8b 44 24 24 01 05 68 d0 b8 00 a1 ?? ?? ?? ?? 89 44 24 34 89 6c 24 24 8b 44 24 34 01 44 24 24 8b 44 24 14 33 44 24 24 89 44 24 24 8b 4c 24 24 } //1
		$a_03_1 = {33 c6 89 44 24 14 8b 44 24 24 31 44 24 14 2b 5c 24 14 89 6c 24 20 8b ?? 24 44 01 44 24 20 29 44 24 18 ff 4c 24 2c 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}