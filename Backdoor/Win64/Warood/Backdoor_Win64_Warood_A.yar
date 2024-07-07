
rule Backdoor_Win64_Warood_A{
	meta:
		description = "Backdoor:Win64/Warood.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {3c 3f 74 3d 3c 47 75 1e 80 7c 3b 01 45 75 17 80 7c 3b 02 54 75 10 } //1
		$a_01_1 = {3c 6c 74 04 3c 72 75 7d 44 8b 44 24 34 41 8d 40 ff 3d fd ff 00 00 77 6d } //1
		$a_01_2 = {48 b8 63 6f 6e 6e 65 63 74 00 48 89 44 24 20 } //1
		$a_01_3 = {64 69 72 3d 69 6e 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 20 70 72 6f 74 6f 63 6f 6c 3d 55 44 50 20 6c 6f 63 61 6c 70 6f 72 74 3d 25 75 } //1 dir=in action=allow protocol=UDP localport=%u
		$a_01_4 = {2f 6c 6f 67 6f 2e 67 69 66 3f 6d 3d } //1 /logo.gif?m=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}