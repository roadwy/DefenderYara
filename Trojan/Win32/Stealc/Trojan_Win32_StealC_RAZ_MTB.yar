
rule Trojan_Win32_StealC_RAZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.RAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 03 44 24 38 8d 14 2b 33 ca 89 44 24 18 89 4c 24 14 89 35 84 50 7b 00 8b 44 24 18 01 05 84 50 7b 00 a1 ?? ?? ?? ?? 89 44 24 28 89 74 24 18 8b 44 24 28 01 44 24 18 8b 44 24 14 33 44 24 18 89 44 24 18 } //1
		$a_03_1 = {33 f0 8b 44 24 ?? 33 c6 2b d8 81 c5 47 86 c8 61 ff 4c 24 20 89 44 24 14 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}