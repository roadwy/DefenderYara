
rule Trojan_Win32_Ursnif_PVK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 0a 8d 84 30 ?? ?? ?? ?? 03 c0 0f b7 f0 81 c1 60 d6 2e 01 8b c6 2b 45 f8 89 0a } //2
		$a_00_1 = {8b 45 fc 8b 4d dc 33 f8 2b df 8b 7d f8 81 c7 47 86 c8 61 83 6d f4 01 89 7d f8 0f 85 } //2
		$a_02_2 = {69 f6 35 0e 01 00 8b 54 24 10 81 c1 30 48 18 01 0f b7 f8 89 0a 90 09 06 00 8b 0d } //2
		$a_02_3 = {30 41 04 8b [0-05] 03 c1 83 e0 03 0f b6 ?? 05 [0-04] 30 41 05 81 fa e2 02 00 00 } //2
		$a_02_4 = {2b c7 2b c6 2d 82 ca 00 00 81 c5 ?? ?? ?? ?? 8b f0 2b f1 89 2b 90 09 07 00 0f b6 0d } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2) >=2
 
}