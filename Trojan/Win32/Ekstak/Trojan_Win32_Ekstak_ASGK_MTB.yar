
rule Trojan_Win32_Ekstak_ASGK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 ec 18 53 56 57 a1 ?? ?? 4c 00 c1 e0 03 0b 05 ?? ?? 4c 00 89 45 ec c7 45 f0 00 00 00 00 df 6d ec dd 1d ?? ?? 4c 00 8b 0d ?? ?? 4c 00 33 0d ?? ?? 4c 00 d1 e1 } //4
		$a_03_1 = {8b d8 85 db 74 2a ff 15 ?? ?? 65 00 6a 00 6a 00 68 ?? ?? 65 00 68 ?? ?? 85 00 a3 ?? ?? 65 00 ff d3 ff 15 ?? ?? 65 00 48 5b f7 d8 1b c0 f7 d8 c3 } //2
		$a_01_2 = {7b 63 66 35 65 62 66 34 36 2d 65 33 62 36 2d 34 34 39 61 2d 62 35 36 62 2d 34 33 66 35 36 38 66 38 37 38 31 34 7d } //2 {cf5ebf46-e3b6-449a-b56b-43f568f87814}
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}