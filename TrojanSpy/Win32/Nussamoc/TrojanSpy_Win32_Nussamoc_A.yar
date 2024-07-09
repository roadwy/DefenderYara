
rule TrojanSpy_Win32_Nussamoc_A{
	meta:
		description = "TrojanSpy:Win32/Nussamoc.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {d7 07 76 05 e8 ?? ?? ff ff 66 81 ?? ?? ?? ?? 00 d7 07 76 17 } //2
		$a_01_1 = {76 26 be 01 00 00 00 8d 45 f4 8b 55 fc 8a 54 32 ff 80 f2 01 } //2
		$a_03_2 = {74 16 68 a0 68 06 00 e8 ?? ?? ?? ?? 8b d7 8b 45 fc } //1
		$a_01_3 = {69 64 2e 70 68 70 3f 72 61 6e 64 6f 6d 3d 00 } //1
		$a_01_4 = {75 70 64 61 74 65 2e 70 68 70 3f 6f 73 3d 00 } //1
		$a_01_5 = {6e 61 6d 65 3d 22 66 69 6c 65 6e 61 6d 65 31 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 70 61 73 73 2e 74 78 74 22 } //1 name="filename1"; filename="pass.txt"
		$a_01_6 = {6e 61 6d 65 3d 22 66 69 6c 65 6e 61 6d 65 32 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 73 63 72 65 65 6e 2e 6a 70 67 22 } //1 name="filename2"; filename="screen.jpg"
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}