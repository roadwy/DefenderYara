
rule Trojan_Win32_PsDrog_A_MTB{
	meta:
		description = "Trojan:Win32/PsDrog.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {a1 d8 7b 54 00 25 ?? ?? ?? ?? 8a 80 08 5f 54 00 8b 15 d8 7b 54 00 30 82 44 36 46 00 ff 05 d8 7b 54 00 81 3d d8 7b 54 00 c2 28 0e 00 75 } //2
		$a_03_1 = {b8 23 00 00 00 e8 e6 11 fa ff ba bc 1a 46 00 8a 14 02 8d 45 ec e8 ?? ?? ?? ?? 8b 55 ec b8 e0 7b 54 00 e8 ?? ?? ?? ?? ff 05 d8 7b 54 00 83 3d d8 7b 54 00 20 75 } //2
		$a_01_2 = {2d 65 70 20 62 79 70 61 73 73 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 66 69 6c 65 } //2 -ep bypass -windowstyle hidden -file
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}