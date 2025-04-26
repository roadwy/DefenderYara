
rule Trojan_Win32_Neoreblamy_K_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 40 c1 e0 00 0f b6 44 05 ?? 83 c8 ?? 33 c9 41 c1 e1 00 0f b6 4c 0d ?? 83 e1 ?? 2b c1 33 c9 41 6b c9 00 0f b6 4c 0d ?? 66 89 44 4d } //1
		$a_81_1 = {49 20 62 65 63 6f 6d 65 20 74 68 65 20 67 75 79 } //1 I become the guy
		$a_81_2 = {4f 68 2c 20 6d 79 20 6b 65 79 62 6f 61 72 64 } //1 Oh, my keyboard
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}