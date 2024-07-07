
rule Backdoor_Win32_Warood_A{
	meta:
		description = "Backdoor:Win32/Warood.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {80 f9 3f 74 39 80 f9 47 75 22 80 7c 3e 01 45 75 1b 80 7c 3e 02 54 75 14 } //1
		$a_01_1 = {81 7c 3e 01 72 61 77 64 75 75 81 7c 3e 05 6f 6f 72 20 75 6b 83 c6 09 } //1
		$a_01_2 = {81 3a 2f 6c 6f 67 0f 85 e0 00 00 00 81 7a 04 6f 2e 67 69 0f 85 d3 00 00 00 81 7a 08 66 3f 6d 3d } //1
		$a_01_3 = {3c 6c 74 04 3c 72 75 6e 8b 4d e0 8d 41 ff 3d fd ff 00 00 77 61 } //1
		$a_01_4 = {64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 74 6f 63 6f 6c 3d 55 44 50 20 6c 6f 63 61 6c 70 6f 72 74 3d 25 75 } //1 dir=in action=allow protocol=UDP localport=%u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}