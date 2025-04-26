
rule Trojan_Win32_GandCrab_KDS_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.KDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b cb 8b c3 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 1e 33 c8 2b f2 2b f9 45 83 fd 20 72 } //2
		$a_02_1 = {8d 81 50 7c 42 00 8a 10 8d b6 50 7c 42 00 8a 1e 41 88 18 88 16 89 0d ?? ?? ?? ?? 3b cf 0f 85 90 09 16 00 8b 0d ?? ?? ?? ?? 81 25 ?? ?? ?? ?? ff 00 00 00 8b 35 } //2
		$a_02_2 = {8a 8e d0 f7 b1 00 81 e7 ff 00 00 00 89 3d ?? ?? ?? ?? 8a 87 d0 f7 b1 00 88 86 d0 f7 b1 00 46 88 8f d0 f7 b1 00 89 35 d0 f8 b1 00 81 fe 00 01 00 00 0f 85 90 09 0c 00 8b 35 ?? ?? ?? ?? 8b 3d } //2
		$a_00_3 = {8a 82 20 ea 42 00 8a 8e 20 ea 42 00 88 86 20 ea 42 00 88 8a 20 ea 42 00 0f b6 9e 20 ea 42 00 0f b6 c1 03 d8 81 fa 2e 0c 00 00 73 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}