
rule Virus_Win32_Teazodo_A{
	meta:
		description = "Virus:Win32/Teazodo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0b 00 00 "
		
	strings :
		$a_00_0 = {b0 73 b2 5c b1 64 } //2
		$a_00_1 = {83 c1 01 83 c2 01 38 1c 31 74 f5 83 fa 37 77 } //2
		$a_02_2 = {66 c7 86 d0 00 00 00 50 45 eb 0e 83 f8 ?? 75 09 66 c7 86 d8 00 00 00 50 45 } //2
		$a_02_3 = {80 38 c6 75 05 38 50 01 74 ?? 83 c1 01 83 c0 01 81 f9 80 00 00 00 72 e8 eb } //2
		$a_02_4 = {6a 00 6a 18 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 8b 54 24 ?? 8b 44 24 ?? 52 56 50 ff 15 } //2
		$a_00_5 = {73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6c 00 6f 00 67 00 6f 00 6e 00 75 00 69 00 2e 00 65 00 78 00 65 00 } //1 s\system32\logonui.exe
		$a_00_6 = {39 00 46 00 34 00 45 00 43 00 45 00 43 00 38 00 2d 00 34 00 31 00 32 00 36 00 2d 00 34 00 61 00 33 00 61 00 2d 00 38 00 39 00 35 00 30 00 2d 00 42 00 38 00 30 00 38 00 39 00 43 00 32 00 42 00 34 00 38 00 33 00 32 00 } //2 9F4ECEC8-4126-4a3a-8950-B8089C2B4832
		$a_00_7 = {25 00 63 00 3a 00 5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 72 00 5c 00 } //1 %c:\Recycler\
		$a_00_8 = {6c 6f 72 74 6e 6f 43 67 75 62 65 44 6d 65 74 73 79 53 77 5a } //2 lortnoCgubeDmetsySwZ
		$a_00_9 = {43 67 66 55 72 6c 3d 68 74 74 70 3a 2f 2f } //1 CgfUrl=http://
		$a_00_10 = {5c 63 6f 64 65 5c 64 6f 77 6e 6c 6f 61 64 65 72 69 6e 73 74 61 6c 6c 65 72 5c } //2 \code\downloaderinstaller\
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*2+(#a_00_9  & 1)*1+(#a_00_10  & 1)*2) >=4
 
}