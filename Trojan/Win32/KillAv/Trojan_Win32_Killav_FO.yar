
rule Trojan_Win32_Killav_FO{
	meta:
		description = "Trojan:Win32/Killav.FO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 56 47 00 6a ff 68 00 00 00 00 8d 4d 00 e8 00 00 00 00 85 c0 0f 84 } //3
		$a_03_1 = {51 50 68 38 04 00 00 ff 15 ?? ?? ?? ?? 8b e8 85 ed 0f 84 ?? ?? ?? ?? 33 c0 6a 1c } //2
		$a_03_2 = {83 f8 10 74 11 83 f8 20 74 0c 83 f8 40 74 07 3d 80 00 00 00 75 ?? 8b 44 24 ?? 6a 04 68 00 30 00 00 50 6a 00 ff 15 } //2
		$a_01_3 = {75 70 64 61 74 65 2e 65 78 65 00 00 41 56 49 52 41 00 00 00 61 76 67 75 70 64 2e 65 78 65 } //1
		$a_01_4 = {43 3a 5c 61 76 75 62 5c 52 65 6c 65 61 73 65 5c 61 76 75 62 2e 70 64 62 } //1 C:\avub\Release\avub.pdb
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}