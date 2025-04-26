
rule PWS_Win32_Wowsteal_UV{
	meta:
		description = "PWS:Win32/Wowsteal.UV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {4a 50 c6 45 ?? 53 ff 75 e8 c6 45 ?? 5a c6 45 ?? 4c c6 45 ?? 2a c6 45 ?? 2a c6 45 ?? 2a } //4
		$a_03_1 = {6a 09 50 ff 35 ?? ?? ?? ?? c6 45 ?? 4d c6 45 ?? 5a c6 45 ?? 90 90 88 5d ?? c6 45 f0 03 88 5d f1 } //4
		$a_01_2 = {25 64 25 64 78 78 78 2e 64 6c 6c 00 78 78 78 2e 64 6c 6c } //2
		$a_03_3 = {6b 61 2e 69 6e 69 [0-05] 71 72 77 6f 77 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=8
 
}