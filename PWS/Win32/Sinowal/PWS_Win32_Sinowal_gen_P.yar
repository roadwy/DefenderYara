
rule PWS_Win32_Sinowal_gen_P{
	meta:
		description = "PWS:Win32/Sinowal.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {8b 65 1c 68 00 80 00 00 6a 00 ff 75 18 ff 75 e0 8b 45 10 ff e0 } //2
		$a_01_1 = {8b 45 10 2b ca ff e0 } //2
		$a_01_2 = {c7 45 f0 88 6a 3f 24 } //2
		$a_01_3 = {03 d0 8b 4d 08 03 4d fc 88 11 } //1
		$a_01_4 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 64 } //1
		$a_03_5 = {b8 00 00 00 00 05 ?? ?? ?? ?? (50|83 ec 04 89 ?? 24 )} //1
		$a_01_6 = {0f b7 51 12 81 e2 00 20 00 00 } //1
		$a_01_7 = {b8 00 00 d9 6e 0d a1 eb 00 00 } //1
		$a_03_8 = {89 45 f0 b8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 45 f4 90 09 0a 00 b8 ?? ?? ?? ?? 2d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1) >=4
 
}