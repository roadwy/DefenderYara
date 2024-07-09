
rule PWS_Win32_Karagany_A{
	meta:
		description = "PWS:Win32/Karagany.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 50 4c 49 42 2e 64 6c 6c 00 45 78 70 6f 72 74 44 61 74 61 00 } //3
		$a_03_1 = {88 0c 02 4f 75 ?? c7 45 fc 64 a5 00 00 8b 75 f0 85 f6 7c } //1
		$a_01_2 = {72 6f 62 65 72 74 32 34 39 66 73 64 29 61 66 38 2e 3f 73 66 32 65 61 79 61 3b 73 64 24 25 38 35 30 33 34 67 73 6e 25 40 23 21 61 66 73 67 73 6a 64 67 3b 69 61 77 65 3b 6f 74 69 67 6b 62 61 72 72 } //1 robert249fsd)af8.?sf2eaya;sd$%85034gsn%@#!afsgsjdg;iawe;otigkbarr
		$a_01_3 = {33 d2 8a d3 b9 69 00 00 00 2b ca 88 4c 30 ff 46 4f 75 } //1
		$a_03_4 = {8b 13 8a 54 32 ff 80 f2 5c 88 54 30 ff 46 4f 75 ?? 8b 03 0f b6 70 02 8b 03 0f b6 78 03 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}