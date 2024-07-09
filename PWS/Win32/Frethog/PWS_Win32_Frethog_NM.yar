
rule PWS_Win32_Frethog_NM{
	meta:
		description = "PWS:Win32/Frethog.NM,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {00 64 6e 66 2e 65 78 65 00 } //1
		$a_00_1 = {73 62 61 6e 6e 65 72 3d 79 65 73 26 6c 6f 67 69 6e 6e 61 6d 65 3d 64 66 } //1 sbanner=yes&loginname=df
		$a_00_2 = {73 65 64 2e 64 72 61 75 47 65 6d 61 47 } //1 sed.drauGemaG
		$a_00_3 = {47 4f 4f 44 42 4f 59 } //1 GOODBOY
		$a_02_4 = {68 22 74 af 00 68 22 74 a0 00 e8 ?? ?? 00 00 6a 06 68 ?? ?? 00 10 68 ?? ?? 00 10 68 3c 94 cf 00 68 3c 94 a9 00 e8 ?? ?? 00 00 6a 13 68 ?? ?? 00 10 68 ?? ?? 00 10 68 5a 45 b3 00 68 1a 68 a0 00 e8 ?? ?? 00 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*10) >=13
 
}