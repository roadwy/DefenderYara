
rule Trojan_Win32_Killav_BY{
	meta:
		description = "Trojan:Win32/Killav.BY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 10 27 00 00 0f 82 ?? ?? 00 00 3d c0 ff 01 00 0f 87 ?? ?? 00 00 a1 ?? ?? 40 00 3d 10 27 00 00 0f 82 ?? ?? 00 00 3d c0 ff 01 00 } //1
		$a_01_1 = {be c8 62 2b 7a ba 4a e8 93 df eb 03 } //1
		$a_01_2 = {8b 32 3b 31 75 12 83 e8 04 83 c1 04 83 c2 04 83 f8 04 73 ec } //1
		$a_01_3 = {8a 08 83 c0 01 84 c9 75 f7 2b c2 3d 8c 00 00 00 0f 87 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}