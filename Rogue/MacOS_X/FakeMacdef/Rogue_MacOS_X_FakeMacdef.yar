
rule Rogue_MacOS_X_FakeMacdef{
	meta:
		description = "Rogue:MacOS_X/FakeMacdef,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2f 73 6f 66 74 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00 } //2 瑨灴⼺┯⽀慭⽣潳瑦瀮灨愿晦摩┽@
		$a_00_1 = {63 64 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 3b 75 6e 7a 69 70 20 25 40 3b 72 6d 20 2d 72 66 20 5f 5f 4d 41 43 4f 53 58 } //2 cd /Applications;unzip %@;rm -rf __MACOSX
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule Rogue_MacOS_X_FakeMacdef_2{
	meta:
		description = "Rogue:MacOS_X/FakeMacdef,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2e 70 68 70 25 40 00 } //2
		$a_00_1 = {3f 76 3d 25 40 26 61 66 66 69 64 3d 25 40 26 64 61 74 61 3d 25 40 00 } //2
		$a_03_2 = {89 54 24 04 89 04 24 e8 90 01 04 83 f8 01 19 f6 83 e6 02 46 8b 83 90 01 04 89 44 24 04 8b 83 90 01 04 89 04 24 e8 90 00 } //2
		$a_03_3 = {8b 7d 08 0f b6 75 10 c6 87 90 01 02 00 00 00 c7 44 24 08 00 00 80 3e 8b 83 90 01 04 89 44 24 04 89 3c 24 e8 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}
rule Rogue_MacOS_X_FakeMacdef_3{
	meta:
		description = "Rogue:MacOS_X/FakeMacdef,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 40 2f 6d 61 63 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00 } //2
		$a_00_1 = {68 74 74 70 3a 2f 2f 25 40 2f 69 2e 70 68 70 3f 61 66 66 69 64 3d 25 40 00 } //2
		$a_03_2 = {89 54 24 04 89 04 24 e8 90 01 04 83 f8 01 19 db 83 e3 02 43 a1 90 01 04 89 44 24 04 a1 90 01 04 89 04 24 e8 90 00 } //2
		$a_03_3 = {8b 75 08 0f b6 5d 10 90 03 08 06 c6 86 90 01 02 00 00 00 c6 46 90 01 01 00 c7 44 24 08 00 00 80 3e a1 90 01 04 89 44 24 04 89 34 24 e8 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=4
 
}