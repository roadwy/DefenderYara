
rule PWS_Win32_Whoran_A{
	meta:
		description = "PWS:Win32/Whoran.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 0b 00 00 "
		
	strings :
		$a_03_0 = {83 c9 ff f2 ae f7 d1 49 85 c9 7e 21 8a 4c 14 ?? 8d 7c 24 ?? 80 f1 ?? 33 c0 88 8c 14 ?? 01 00 00 83 c9 ff 42 f2 ae } //8
		$a_01_1 = {7b 54 4b 7d 7a 7a 6d 66 } //8 {TK}zzmf
		$a_00_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //2 Content-Type: application/x-www-form-urlencoded
		$a_01_3 = {4d 53 44 4e 20 53 75 72 66 42 65 61 72 } //1 MSDN SurfBear
		$a_01_4 = {72 61 76 6d 6f 6e 2e 65 78 65 } //1 ravmon.exe
		$a_01_5 = {73 79 6d 61 6e 74 65 63 2e 65 78 65 } //1 symantec.exe
		$a_01_6 = {6b 61 76 33 32 2e 65 78 65 } //1 kav32.exe
		$a_01_7 = {26 75 72 6c 3d } //1 &url=
		$a_01_8 = {26 70 61 73 73 3d } //2 &pass=
		$a_01_9 = {26 75 73 65 72 3d } //1 &user=
		$a_01_10 = {26 70 63 6e 61 6d 65 3d } //1 &pcname=
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*8+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}