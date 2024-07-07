
rule Trojan_Win32_ArkeiStealer_DK_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {6b 65 79 3d 31 32 35 34 37 38 38 32 34 35 31 35 41 44 4e 78 75 32 63 63 62 77 65 } //key=125478824515ADNxu2ccbwe  3
		$a_80_1 = {6d 73 67 3d 4e 6f 2d 45 78 65 73 2d 46 6f 75 6e 64 2d 54 6f 2d 52 75 6e } //msg=No-Exes-Found-To-Run  3
		$a_80_2 = {62 72 79 65 78 68 73 67 2e 78 79 7a } //bryexhsg.xyz  3
		$a_80_3 = {26 69 70 3d 26 6f 69 64 3d 33 } //&ip=&oid=3  3
		$a_80_4 = {61 64 64 49 6e 73 74 61 6c 6c 2e 70 68 70 3f } //addInstall.php?  3
		$a_80_5 = {2f 64 65 76 2f 72 61 6e 64 6f 6d } ///dev/random  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}