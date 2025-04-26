
rule Trojan_Win32_Alureon_gen_L{
	meta:
		description = "Trojan:Win32/Alureon.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {eb 40 8b 4d fc 83 c1 03 89 4d fc 68 ?? ?? ?? ?? 8b 55 fc 52 e8 ?? ?? 00 00 83 c4 08 89 45 f8 83 7d f8 00 } //2
		$a_01_1 = {73 1c 8b 4d 08 03 4d f8 0f be 11 33 55 0c 88 55 f0 8b 45 f4 03 45 f8 8a 4d f0 88 08 eb d3 } //2
		$a_01_2 = {3f 63 3d 00 26 6d 6b 3d 00 } //1
		$a_01_3 = {66 69 72 65 73 6f 78 2e 64 6c 6c 00 3f 3f 52 } //2
		$a_01_4 = {75 72 6c 2d 3e 20 25 73 0a 0a 72 65 66 20 2d 3e } //2
		$a_01_5 = {53 65 6e 64 50 6f 73 74 52 61 77 } //1 SendPostRaw
		$a_01_6 = {46 69 72 73 74 2d 43 6c 69 63 6b 3a 25 64 } //1 First-Click:%d
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}